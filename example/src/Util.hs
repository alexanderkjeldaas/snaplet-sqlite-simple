{-# LANGUAGE OverloadedStrings #-}

module Util (
    reader
  , logFail
  ) where

import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Text.Read as T

import           Snap.Core
import           Snap.Snaplet
import           Snap.Snaplet.Auth
import           Application

type H = Handler App (AuthManager App)

reader :: T.Reader a -> T.Text -> Either String a
reader p s =
  case p s of
    Right (a, "") -> return a
    Right (_, _) -> Left "readParser: input not exhausted"
    Left e -> Left e

-- | Log Either Left values or do nothing.  To be used in situations
-- where to user shouldn't see an error (either due to it being
-- irrelevant or due to security) but we want to leave a trace of the
-- error case anyway.
logFail :: Either String () -> H ()
logFail = either (logError . T.encodeUtf8 . T.pack)  (\_ -> return ())
