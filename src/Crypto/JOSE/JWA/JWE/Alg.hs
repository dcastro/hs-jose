-- Copyright (C) 2013, 2014  Fraser Tweedale
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

JSON Web Encryption algorithms.

-}
module Crypto.JOSE.JWA.JWE.Alg
  ( Alg(..)
  ) where

import qualified Crypto.JOSE.TH
import Data.Aeson (FromJSON(..), ToJSON(..))


-- | RFC 7518 §4.1.  "alg" (Algorithm) Header Parameter Values for JWE
--
-- This section is shuffled off into its own module to avoid
-- circular import via Crypto.JOSE.JWK, which needs Alg.
--
data Alg
  = RSA1_5 |
    RSA_OAEP |
    RSA_OAEP_256 |
    A128KW |
    A192KW |
    A256KW |
    Dir |
    ECDH_ES |
    ECDH_ES_A128KW |
    ECDH_ES_A192KW |
    ECDH_ES_A256KW |
    A128GCMKW |
    A192GCMKW |
    A256GCMKW |
    PBES2_HS256_A128KW |
    PBES2_HS384_A192KW |
    PBES2_HS512_A256KW
  deriving (Eq, Ord, Show)
instance FromJSON Alg where
  parseJSON s
    | (s == "RSA1_5") = pure RSA1_5
    | (s == "RSA-OAEP") = pure RSA_OAEP
    | (s == "RSA-OAEP-256") = pure RSA_OAEP_256
    | (s == "A128KW") = pure A128KW
    | (s == "A192KW") = pure A192KW
    | (s == "A256KW") = pure A256KW
    | (s == "dir") = pure Dir
    | (s == "ECDH-ES") = pure ECDH_ES
    | (s == "ECDH-ES+A128KW") = pure ECDH_ES_A128KW
    | (s == "ECDH-ES+A192KW") = pure ECDH_ES_A192KW
    | (s == "ECDH-ES+A256KW") = pure ECDH_ES_A256KW
    | (s == "A128GCMKW") = pure A128GCMKW
    | (s == "A192GCMKW") = pure A192GCMKW
    | (s == "A256GCMKW") = pure A256GCMKW
    | (s == "PBES2-HS256+A128KW") = pure PBES2_HS256_A128KW
    | (s == "PBES2-HS384+A192KW") = pure PBES2_HS384_A192KW
    | (s == "PBES2-HS512+A256KW") = pure PBES2_HS512_A256KW
    | otherwise
    = fail
        ("unrecognised value; expected: "
           ++
             "[RSA1_5,RSA-OAEP,RSA-OAEP-256,A128KW,A192KW,A256KW,dir,ECDH-ES,ECDH-ES+A128KW,ECDH-ES+A192KW,ECDH-ES+A256KW,A128GCMKW,A192GCMKW,A256GCMKW,PBES2-HS256+A128KW,PBES2-HS384+A192KW,PBES2-HS512+A256KW]")
instance ToJSON Alg where
  toJSON RSA1_5 = "RSA1_5"
  toJSON RSA_OAEP = "RSA-OAEP"
  toJSON RSA_OAEP_256 = "RSA-OAEP-256"
  toJSON A128KW = "A128KW"
  toJSON A192KW = "A192KW"
  toJSON A256KW = "A256KW"
  toJSON Dir = "dir"
  toJSON ECDH_ES = "ECDH-ES"
  toJSON ECDH_ES_A128KW = "ECDH-ES+A128KW"
  toJSON ECDH_ES_A192KW = "ECDH-ES+A192KW"
  toJSON ECDH_ES_A256KW = "ECDH-ES+A256KW"
  toJSON A128GCMKW = "A128GCMKW"
  toJSON A192GCMKW = "A192GCMKW"
  toJSON A256GCMKW = "A256GCMKW"
  toJSON PBES2_HS256_A128KW = "PBES2-HS256+A128KW"
  toJSON PBES2_HS384_A192KW = "PBES2-HS384+A192KW"
  toJSON PBES2_HS512_A256KW = "PBES2-HS512+A256KW"
