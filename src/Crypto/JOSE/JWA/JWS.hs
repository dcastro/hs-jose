-- Copyright (C) 2013  Fraser Tweedale
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

{-# LANGUAGE OverloadedStrings #-}

{-|

JSON Web Signature algorithms.

-}
module Crypto.JOSE.JWA.JWS
  ( Alg(..)
  ) where

import Data.Aeson (FromJSON(..), ToJSON(..))


-- | RFC 7518 §3.1.  "alg" (Algorithm) Header Parameters Values for JWS
--
data Alg
  = HS256 |
    HS384 |
    HS512 |
    RS256 |
    RS384 |
    RS512 |
    ES256 |
    ES384 |
    ES512 |
    ES256K |
    PS256 |
    PS384 |
    PS512 |
    None |
    EdDSA
  deriving (Eq, Ord, Show)
instance FromJSON Alg where
  parseJSON s
    | (s == "HS256") = pure HS256
    | (s == "HS384") = pure HS384
    | (s == "HS512") = pure HS512
    | (s == "RS256") = pure RS256
    | (s == "RS384") = pure RS384
    | (s == "RS512") = pure RS512
    | (s == "ES256") = pure ES256
    | (s == "ES384") = pure ES384
    | (s == "ES512") = pure ES512
    | (s == "ES256K") = pure ES256K
    | (s == "PS256") = pure PS256
    | (s == "PS384") = pure PS384
    | (s == "PS512") = pure PS512
    | (s == "none") = pure None
    | (s == "EdDSA") = pure EdDSA
    | otherwise
    = fail
        ("unrecognised value; expected: "
           ++
             "[HS256,HS384,HS512,RS256,RS384,RS512,ES256,ES384,ES512,ES256K,PS256,PS384,PS512,none,EdDSA]")
instance ToJSON Alg where
  toJSON HS256 = "HS256"
  toJSON HS384 = "HS384"
  toJSON HS512 = "HS512"
  toJSON RS256 = "RS256"
  toJSON RS384 = "RS384"
  toJSON RS512 = "RS512"
  toJSON ES256 = "ES256"
  toJSON ES384 = "ES384"
  toJSON ES512 = "ES512"
  toJSON ES256K = "ES256K"
  toJSON PS256 = "PS256"
  toJSON PS384 = "PS384"
  toJSON PS512 = "PS512"
  toJSON None = "none"
  toJSON EdDSA = "EdDSA"
