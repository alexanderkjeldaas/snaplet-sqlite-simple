{-# LANGUAGE BangPatterns      #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE ScopedTypeVariables   #-}

{-|

This module allows you to use the auth snaplet with your user database
stored in a SQLite database.  When you run your application with this
snaplet, a config file will be copied into the the
@snaplets/sqlite-auth@ directory.  This file contains all of the
configurable options for the snaplet and allows you to change them
without recompiling your application.

To use this snaplet in your application enable the session, sqlite,
and auth snaplets as follows:

> data App = App
>     { ... -- your own application state here
>     , _sess :: Snaplet SessionManager
>     , _db   :: Snaplet Sqlite
>     , _auth :: Snaplet (AuthManager App)
>     }

Then in your initializer you'll have something like this:

> d <- nestSnaplet "db" db sqliteInit
> a <- nestSnaplet "auth" auth $ initSqliteAuth sess d

If you have not already created the database table for users, it will
automatically be created for you the first time you run your
application.

-}

module Snap.Snaplet.Auth.Backends.SqliteSimple
  ( initSqliteAuth
  ) where

------------------------------------------------------------------------------
import           Control.Concurrent
import qualified Data.Configurator as C
import qualified Data.HashMap.Lazy as HM
import           Data.Maybe
import           Data.Text (Text)
import qualified Data.Text as T
import qualified Database.SQLite.Simple as S
import           Database.SQLite.Simple.FromField
import           Database.SQLite.Simple.FromRow
import qualified Database.SQLite.Simple.ToField as S
import           Database.SQLite.Simple.Types
import           Database.SQLite3 (SQLData(..))
import           Paths_snaplet_sqlite_simple
import           Snap
import           Snap.Snaplet.Auth
import           Snap.Snaplet.Session
import           Snap.Snaplet.SqliteSimple
import           Web.ClientSession


data SqliteAuthManager = SqliteAuthManager
    { pamTable       :: AuthTable
    , userRoleTable  :: RoleTable
    , userMetaTable  :: MetaTable
    , pamConnPool    :: MVar S.Connection
    }


------------------------------------------------------------------------------
-- | Initializer for the sqlite backend to the auth snaplet.
--
initSqliteAuth
  :: SnapletLens b SessionManager  -- ^ Lens to the session snaplet
  -> Snaplet Sqlite  -- ^ The sqlite snaplet
  -> SnapletInit b (AuthManager b)
initSqliteAuth sess db = makeSnaplet "sqlite-auth" desc datadir $ do
    config <- getSnapletUserConfig
    authTable <- liftIO $ C.lookupDefault "snap_auth_user" config "authTable"
    roleTable <- liftIO $ C.lookupDefault "snap_auth_user" config "roleTable"
    metaTable <- liftIO $ C.lookupDefault "snap_auth_user" config "metaTable"
    authSettings <- authSettingsFromConfig
    key <- liftIO $ getKey (asSiteKey authSettings)
    let authTableDesc = defAuthTable { authTblName = authTable }
    let roleTableDesc = defRoleTable { roleTblName = roleTable }
    let metaTableDesc = defMetaTable { metaTblName = metaTable }
    let manager = SqliteAuthManager authTableDesc roleTableDesc metaTableDesc $
                                      sqliteConn $ db ^# snapletValue
    liftIO $ createTableIfMissing manager
    rng <- liftIO mkRNG
    return $ AuthManager
      { backend = manager
      , session = sess
      , activeUser = Nothing
      , minPasswdLen = asMinPasswdLen authSettings
      , rememberCookieName = asRememberCookieName authSettings
      , rememberPeriod = asRememberPeriod authSettings
      , siteKey = key
      , lockout = asLockout authSettings
      , randomNumberGenerator = rng
      }
  where
    desc = "An Sqlite backend for user authentication"
    datadir = Just $ liftM (++"/resources/auth") getDataDir


tableExists :: S.Connection -> T.Text -> IO Bool
tableExists conn tblName = do
  r <- S.query conn "SELECT name FROM sqlite_master WHERE type='table' AND name=?" (Only tblName)
  case r of
    [Only (_ :: String)] -> return True
    _ -> return False

createInitialSchema :: S.Connection -> AuthTable -> IO ()
createInitialSchema conn pamTable = do
  let q = Query $ T.concat
          [ "CREATE TABLE ", authTblName pamTable, " (uid INTEGER PRIMARY KEY,"
          , "login text UNIQUE NOT NULL,"
          , "password text,"
          , "activated_at timestamp,suspended_at timestamp,remember_token text,"
          , "login_count INTEGER NOT NULL,failed_login_count INTEGER NOT NULL,"
          , "locked_out_until timestamp,current_login_at timestamp,"
          , "last_login_at timestamp,current_login_ip text,"
          , "last_login_ip text,created_at timestamp,updated_at timestamp);"
          ]
  S.execute_ conn q

versionTable :: AuthTable -> T.Text
versionTable pamTable = T.concat [authTblName pamTable, "_version"]

schemaVersion :: S.Connection -> AuthTable -> IO Int
schemaVersion conn pamTable = do
  let verTbl = versionTable pamTable
  versionExists <- tableExists conn verTbl
  if not versionExists
    then return 0
    else
    do
      let q = T.concat ["SELECT version FROM ", verTbl, " LIMIT 1"]
      [Only v] <- S.query_ conn (Query q) :: IO [Only Int]
      return v

setSchemaVersion :: S.Connection -> AuthTable -> Int -> IO ()
setSchemaVersion conn pamTable v = do
  let q = Query $ T.concat ["UPDATE ", versionTable pamTable, " SET version = ?"]
  S.execute conn q (Only v)

upgradeSchema :: Connection -> AuthTable -> Int -> IO ()
upgradeSchema conn pam fromVersion = do
  ver <- schemaVersion conn pam
  when (ver == fromVersion) (upgrade ver >> setSchemaVersion conn pam (fromVersion+1))
  where
    upgrade 0 = do
      S.execute_ conn (Query $ T.concat ["CREATE TABLE ", versionTable pam, " (version INTEGER)"])
      S.execute_ conn (Query $ T.concat ["INSERT INTO  ", versionTable pam, " VALUES (1)"])

    upgrade 1 = do
      S.execute_ conn (addColumnQ (authColEmail pam))
      S.execute_ conn (addColumnQ (authColResetToken pam))
      S.execute_ conn (addColumnQ (authColResetRequestedAt pam))

    -- upgrade 2 = do
    --   S.execute_ conn (addColumnQ (

    upgrade _ = error "unknown version"

    addColumnQ (c,t) =
      Query $ T.concat [ "ALTER TABLE ", authTblName pam, " ADD COLUMN ", c, " ", t]


------------------------------------------------------------------------------
-- | Create the user table if it doesn't exist.
createTableIfMissing :: SqliteAuthManager -> IO ()
createTableIfMissing SqliteAuthManager{..} = do
    withMVar pamConnPool $ \conn -> do
      authTblExists <- tableExists conn $ authTblName pamTable
      unless authTblExists $ createInitialSchema conn pamTable
      --roleTblExists <- tableExists conn $ authTblName 
      upgradeSchema conn pamTable 0
      upgradeSchema conn pamTable 1


buildUid :: Int -> UserId
buildUid = UserId . T.pack . show

instance FromField UserId where
    fromField f = buildUid <$> fromField f

instance FromField Password where
    fromField f = Encrypted <$> fromField f

instance FromRow AuthUser where
    fromRow =
        AuthUser
        <$> _userId
        <*> _userLogin
        <*> _userEmail
        <*> _userPassword
        <*> _userActivatedAt
        <*> _userSuspendedAt
        <*> _userRememberToken
        <*> _userLoginCount
        <*> _userFailedLoginCount
        <*> _userLockedOutUntil
        <*> _userCurrentLoginAt
        <*> _userLastLoginAt
        <*> _userCurrentLoginIp
        <*> _userLastLoginIp
        <*> _userCreatedAt
        <*> _userUpdatedAt
        <*> _userResetToken
        <*> _userResetRequestedAt
        <*> _userRoles
        <*> _userMeta
      where
        !_userId               = field
        !_userLogin            = field
        !_userEmail            = field
        !_userPassword         = field
        !_userActivatedAt      = field
        !_userSuspendedAt      = field
        !_userRememberToken    = field
        !_userLoginCount       = field
        !_userFailedLoginCount = field
        !_userLockedOutUntil   = field
        !_userCurrentLoginAt   = field
        !_userLastLoginAt      = field
        !_userCurrentLoginIp   = field
        !_userLastLoginIp      = field
        !_userCreatedAt        = field
        !_userUpdatedAt        = field
        !_userResetToken       = field
        !_userResetRequestedAt = field
        !_userRoles            = pure []
        !_userMeta             = pure HM.empty


querySingle :: (ToRow q, FromRow a)
            => MVar S.Connection -> Query -> q -> IO (Maybe a)
querySingle pool q ps = withMVar pool $ \conn -> return . listToMaybe =<<
    S.query conn q ps

authExecute :: ToRow q
            => MVar S.Connection -> Query -> q -> IO ()
authExecute pool q ps = do
    withMVar pool $ \conn -> S.execute conn q ps
    return ()

instance S.ToField Password where
    toField (ClearText bs) = S.toField bs
    toField (Encrypted bs) = S.toField bs


-- | Datatype containing the names of the columns for the authentication table.
data AuthTable
  =  AuthTable
  {  authTblName             :: Text
  ,  authColId               :: (Text, Text)
  ,  authColLogin            :: (Text, Text)
  ,  authColEmail            :: (Text, Text)
  ,  authColPassword         :: (Text, Text)
  ,  authColActivatedAt      :: (Text, Text)
  ,  authColSuspendedAt      :: (Text, Text)
  ,  authColRememberToken    :: (Text, Text)
  ,  authColLoginCount       :: (Text, Text)
  ,  authColFailedLoginCount :: (Text, Text)
  ,  authColLockedOutUntil   :: (Text, Text)
  ,  authColCurrentLoginAt   :: (Text, Text)
  ,  authColLastLoginAt      :: (Text, Text)
  ,  authColCurrentLoginIp   :: (Text, Text)
  ,  authColLastLoginIp      :: (Text, Text)
  ,  authColCreatedAt        :: (Text, Text)
  ,  authColUpdatedAt        :: (Text, Text)
  ,  authColResetToken       :: (Text, Text)
  ,  authColResetRequestedAt :: (Text, Text)
  }

data RoleTable
  =  RoleTable
  {  roleTblName   :: Text
  ,  roleColAuthId :: (Text, Text)
  ,  roleColData   :: (Text, Text)
  }

data MetaTable
  =  MetaTable
  {  metaTblName   :: Text
  ,  metaColAuthId :: (Text, Text)
  ,  metaColKey    :: (Text, Text)
  ,  metaColValue  :: (Text, Text)
  }

-- | Default authentication table layout
defAuthTable :: AuthTable
defAuthTable
  =  AuthTable
  {  authTblName             = "snap_auth_user"
  ,  authColId               = ("uid", "INTEGER PRIMARY KEY")
  ,  authColLogin            = ("login", "text UNIQUE NOT NULL")
  ,  authColEmail            = ("email", "text")
  ,  authColPassword         = ("password", "text")
  ,  authColActivatedAt      = ("activated_at", "timestamp")
  ,  authColSuspendedAt      = ("suspended_at", "timestamp")
  ,  authColRememberToken    = ("remember_token", "text")
  ,  authColLoginCount       = ("login_count", "INTEGER NOT NULL")
  ,  authColFailedLoginCount = ("failed_login_count", "INTEGER NOT NULL")
  ,  authColLockedOutUntil   = ("locked_out_until", "timestamp")
  ,  authColCurrentLoginAt   = ("current_login_at", "timestamp")
  ,  authColLastLoginAt      = ("last_login_at", "timestamp")
  ,  authColCurrentLoginIp   = ("current_login_ip", "text")
  ,  authColLastLoginIp      = ("last_login_ip", "text")
  ,  authColCreatedAt        = ("created_at", "timestamp")
  ,  authColUpdatedAt        = ("updated_at", "timestamp")
  ,  authColResetToken       = ("reset_token", "text")
  ,  authColResetRequestedAt = ("reset_requested_at", "timestamp")
  }

-- | Default authentication role table layout
defRoleTable :: RoleTable
defRoleTable
  =  RoleTable
  {  roleTblName             = "snap_auth_role"
  ,  roleColAuthId           = ("auth_uid", "INTEGER NOT NULL")
  ,  roleColData             = ("data", "text")
  }

-- | Default authentication meta table layout
defMetaTable :: MetaTable
defMetaTable
  =  MetaTable
  {  metaTblName             = "snap_auth_meta"
  ,  metaColAuthId           = ("auth_uid", "INTEGER NOT NULL")
  ,  metaColKey              = ("key", "text")
  ,  metaColValue            = ("key", "text")
  }

-- | List of deconstructors so it's easier to extract column names from an
-- 'AuthTable'.
authColDef :: [(AuthTable -> (Text, Text), AuthUser -> SQLData)]
authColDef =
  [ (authColId              , S.toField . fmap unUid . userId)
  , (authColLogin           , S.toField . userLogin)
  , (authColEmail           , S.toField . userEmail)
  , (authColPassword        , S.toField . userPassword)
  , (authColActivatedAt     , S.toField . userActivatedAt)
  , (authColSuspendedAt     , S.toField . userSuspendedAt)
  , (authColRememberToken   , S.toField . userRememberToken)
  , (authColLoginCount      , S.toField . userLoginCount)
  , (authColFailedLoginCount, S.toField . userFailedLoginCount)
  , (authColLockedOutUntil  , S.toField . userLockedOutUntil)
  , (authColCurrentLoginAt  , S.toField . userCurrentLoginAt)
  , (authColLastLoginAt     , S.toField . userLastLoginAt)
  , (authColCurrentLoginIp  , S.toField . userCurrentLoginIp)
  , (authColLastLoginIp     , S.toField . userLastLoginIp)
  , (authColCreatedAt       , S.toField . userCreatedAt)
  , (authColUpdatedAt       , S.toField . userUpdatedAt)
  , (authColResetToken      , S.toField . userResetToken)
  , (authColResetRequestedAt, S.toField . userResetRequestedAt)
  ]

-- -- | List of deconstructors so it's easier to extract column names from an
-- -- 'AuthTable'.
-- roleColDef :: [(RoleTable -> (Text, Text), AuthUser -> SQLData)]
-- roleColDef =
--   [ (roleColAuthId          , S.toField . fmap unUid . userId)
--   , (roleColData            , S.toField . userEmail)
--   ]

authColNames :: AuthTable -> T.Text
authColNames pam =
  T.intercalate "," . map (\(f,_) -> fst (f pam)) $ authColDef

saveQuery :: AuthTable -> AuthUser -> (Text, [SQLData])
saveQuery at u@AuthUser{..} = maybe insertQuery updateQuery userId
  where
    insertQuery =  (T.concat [ "INSERT INTO "
                             , authTblName at
                             , " ("
                             , T.intercalate "," cols
                             , ") VALUES ("
                             , T.intercalate "," vals
                             , ")"
                             ]
                   , params)
    qval f  = fst (f at) `T.append` " = ?"
    updateQuery uid =
        (T.concat [ "UPDATE "
                  , authTblName at
                  , " SET "
                  , T.intercalate "," (map (qval . fst) $ tail authColDef)
                  , " WHERE "
                  , fst (authColId at)
                  , " = ?"
                  ]
        , params ++ [S.toField $ unUid uid])
    cols = map (fst . ($at) . fst) $ tail authColDef
    vals = map (const "?") cols
    params = map (($u) . snd) $ tail authColDef


------------------------------------------------------------------------------
-- |
instance IAuthBackend SqliteAuthManager where
    save SqliteAuthManager{..} u@AuthUser{..} = do
        let (qstr, params) = saveQuery pamTable u
        withMVar pamConnPool $ \conn -> do
            -- Note that the user INSERT here expects that duplicate
            -- login error checking has been done already at the level
            -- that calls here.
            S.execute conn (Query qstr) params
            let q2 = Query $ T.concat
                     [ "select ", authColNames pamTable, " from "
                     , authTblName pamTable
                     , " where "
                     , fst (authColLogin pamTable)
                     , " = ?"
                     ]
            res <- S.query conn q2 [userLogin]
            case res of
              [savedUser] -> return $ Right savedUser
              _           -> return . Left $ AuthError "snaplet-sqlite-simple: Failed user save"

    lookupByUserId SqliteAuthManager{..} uid = do
        let q = Query $ T.concat
                [ "select ", authColNames pamTable, " from "
                , authTblName pamTable
                , " where "
                , fst (authColId pamTable)
                , " = ?"
                ]
        querySingle pamConnPool q [unUid uid]

    lookupByLogin SqliteAuthManager{..} login = do
        let q = Query $ T.concat
                [ "select ", authColNames pamTable, " from "
                , authTblName pamTable
                , " where "
                , fst (authColLogin pamTable)
                , " = ?"
                ]
        querySingle pamConnPool q [login]

    lookupByRememberToken SqliteAuthManager{..} token = do
        let q = Query $ T.concat
                [ "select ", authColNames pamTable, " from "
                , authTblName pamTable
                , " where "
                , fst (authColRememberToken pamTable)
                , " = ?"
                ]
        querySingle pamConnPool q [token]

    destroy SqliteAuthManager{..} AuthUser{..} = do
        let q = Query $ T.concat
                [ "delete from "
                , authTblName pamTable
                , " where "
                , fst (authColLogin pamTable)
                , " = ?"
                ]
        authExecute pamConnPool q [userLogin]
