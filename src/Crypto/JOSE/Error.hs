-- Copyright (C) 2014-2022  Fraser Tweedale
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

{-|

JOSE error types and helpers.

-}
module Crypto.JOSE.Error
  (
  -- * Running JOSE computations
    runJOSE
  , unwrapJOSE
  , JOSE(..)

  -- * Base error type and class
  , Error(..)
  , AsError(..)

  -- * JOSE compact serialisation errors
  , InvalidNumberOfParts(..), expectedParts, actualParts
  , CompactTextError(..)
  , CompactDecodeError(..)
  , _CompactInvalidNumberOfParts
  , _CompactInvalidText

  ) where

import Numeric.Natural

import Control.Monad.Except (MonadError(..), ExceptT, runExceptT)
import Control.Monad.Trans (MonadIO(liftIO), MonadTrans(lift))
import qualified Crypto.PubKey.RSA as RSA
import Crypto.Error (CryptoError)
import Crypto.Random (MonadRandom(..))
import Control.Lens (Getter, to)
import Control.Lens.TH (makeClassyPrisms, makePrisms)
import qualified Data.Text as T
import qualified Data.Text.Encoding.Error as T
import Control.Lens.Prism
import Data.Text (Text)


-- | The wrong number of parts were found when decoding a
-- compact JOSE object.
--
data InvalidNumberOfParts =
  InvalidNumberOfParts Natural Natural -- ^ expected vs actual parts
  deriving (Eq)

instance Show InvalidNumberOfParts where
  show (InvalidNumberOfParts n m) =
    "Expected " <> show n <> " parts; got " <> show m

-- | Get the expected or actual number of parts.
expectedParts, actualParts :: Getter InvalidNumberOfParts Natural
expectedParts = to $ \(InvalidNumberOfParts n _) -> n
actualParts   = to $ \(InvalidNumberOfParts _ n) -> n


-- | Bad UTF-8 data in a compact object, at the specified index
data CompactTextError = CompactTextError
  Natural
  T.UnicodeException
  deriving (Eq)

instance Show CompactTextError where
  show (CompactTextError n s) =
    "Invalid text at part " <> show n <> ": " <> show s


-- | An error when decoding a JOSE compact object.
-- JSON decoding errors that occur during compact object processing
-- throw 'JSONDecodeError'.
--
data CompactDecodeError
  = CompactInvalidNumberOfParts InvalidNumberOfParts
  | CompactInvalidText CompactTextError
  deriving (Eq)

_CompactInvalidNumberOfParts ::
  Prism' CompactDecodeError InvalidNumberOfParts
_CompactInvalidNumberOfParts =
  prism
    (\x1_aBRR -> CompactInvalidNumberOfParts x1_aBRR)
    ( \x_aBRS ->
        case x_aBRS of
          CompactInvalidNumberOfParts y1_aBRT -> Right y1_aBRT
          _ -> Left x_aBRS
    )
{-# INLINE _CompactInvalidNumberOfParts #-}
_CompactInvalidText :: Prism' CompactDecodeError CompactTextError
_CompactInvalidText =
  prism
    (\x1_aBRU -> CompactInvalidText x1_aBRU)
    ( \x_aBRV ->
        case x_aBRV of
          CompactInvalidText y1_aBRW -> Right y1_aBRW
          _ -> Left x_aBRV
    )
{-# INLINE _CompactInvalidText #-}

instance Show CompactDecodeError where
  show (CompactInvalidNumberOfParts e) = "Invalid number of parts: " <> show e
  show (CompactInvalidText e) = "Invalid text: " <> show e



-- | All the errors that can occur.
--
data Error
  = AlgorithmNotImplemented   -- ^ A requested algorithm is not implemented
  | AlgorithmMismatch String  -- ^ A requested algorithm cannot be used
  | KeyMismatch T.Text        -- ^ Wrong type of key was given
  | KeySizeTooSmall           -- ^ Key size is too small
  | OtherPrimesNotSupported   -- ^ RSA private key with >2 primes not supported
  | RSAError RSA.Error        -- ^ RSA encryption, decryption or signing error
  | CryptoError CryptoError   -- ^ Various cryptonite library error cases
  | CompactDecodeError CompactDecodeError
  -- ^ Wrong number of parts in compact serialisation
  | JSONDecodeError String    -- ^ JSON (Aeson) decoding error
  | NoUsableKeys              -- ^ No usable keys were found in the key store
  | JWSCritUnprotected
  | JWSNoValidSignatures
  -- ^ 'AnyValidated' policy active, and no valid signature encountered
  | JWSInvalidSignature
  -- ^ 'AllValidated' policy active, and invalid signature encountered
  | JWSNoSignatures
  -- ^ 'AllValidated' policy active, and there were no signatures on object
  --   that matched the allowed algorithms
  deriving (Eq, Show)

class AsError r_aNtA where
  _Error :: Prism' r_aNtA Error
  _AlgorithmNotImplemented :: Prism' r_aNtA ()
  _AlgorithmMismatch :: Prism' r_aNtA String
  _KeyMismatch :: Prism' r_aNtA Text
  _KeySizeTooSmall :: Prism' r_aNtA ()
  _OtherPrimesNotSupported :: Prism' r_aNtA ()
  _RSAError :: Prism' r_aNtA RSA.Error
  _CryptoError :: Prism' r_aNtA CryptoError
  _CompactDecodeError :: Prism' r_aNtA CompactDecodeError
  _JSONDecodeError :: Prism' r_aNtA String
  _NoUsableKeys :: Prism' r_aNtA ()
  _JWSCritUnprotected :: Prism' r_aNtA ()
  _JWSNoValidSignatures :: Prism' r_aNtA ()
  _JWSInvalidSignature :: Prism' r_aNtA ()
  _JWSNoSignatures :: Prism' r_aNtA ()
  _AlgorithmNotImplemented = (.) _Error _AlgorithmNotImplemented
  _AlgorithmMismatch = (.) _Error _AlgorithmMismatch
  _KeyMismatch = (.) _Error _KeyMismatch
  _KeySizeTooSmall = (.) _Error _KeySizeTooSmall
  _OtherPrimesNotSupported = (.) _Error _OtherPrimesNotSupported
  _RSAError = (.) _Error _RSAError
  _CryptoError = (.) _Error _CryptoError
  _CompactDecodeError = (.) _Error _CompactDecodeError
  _JSONDecodeError = (.) _Error _JSONDecodeError
  _NoUsableKeys = (.) _Error _NoUsableKeys
  _JWSCritUnprotected = (.) _Error _JWSCritUnprotected
  _JWSNoValidSignatures = (.) _Error _JWSNoValidSignatures
  _JWSInvalidSignature = (.) _Error _JWSInvalidSignature
  _JWSNoSignatures = (.) _Error _JWSNoSignatures
instance AsError Error where
  _Error = id
  _AlgorithmNotImplemented =
    prism
      (\() -> AlgorithmNotImplemented)
      ( \x_aNtB ->
          case x_aNtB of
            AlgorithmNotImplemented -> Right ()
            _ -> Left x_aNtB
      )
  _AlgorithmMismatch =
    prism
      (\x1_aNtC -> AlgorithmMismatch x1_aNtC)
      ( \x_aNtD ->
          case x_aNtD of
            AlgorithmMismatch y1_aNtE -> Right y1_aNtE
            _ -> Left x_aNtD
      )
  _KeyMismatch =
    prism
      (\x1_aNtF -> KeyMismatch x1_aNtF)
      ( \x_aNtG ->
          case x_aNtG of
            KeyMismatch y1_aNtH -> Right y1_aNtH
            _ -> Left x_aNtG
      )
  _KeySizeTooSmall =
    prism
      (\() -> KeySizeTooSmall)
      ( \x_aNtI ->
          case x_aNtI of
            KeySizeTooSmall -> Right ()
            _ -> Left x_aNtI
      )
  _OtherPrimesNotSupported =
    prism
      (\() -> OtherPrimesNotSupported)
      ( \x_aNtJ ->
          case x_aNtJ of
            OtherPrimesNotSupported -> Right ()
            _ -> Left x_aNtJ
      )
  _RSAError =
    prism
      (\x1_aNtK -> RSAError x1_aNtK)
      ( \x_aNtL ->
          case x_aNtL of
            RSAError y1_aNtM -> Right y1_aNtM
            _ -> Left x_aNtL
      )
  _CryptoError =
    prism
      (\x1_aNtN -> CryptoError x1_aNtN)
      ( \x_aNtO ->
          case x_aNtO of
            CryptoError y1_aNtP -> Right y1_aNtP
            _ -> Left x_aNtO
      )
  _CompactDecodeError =
    prism
      (\x1_aNtQ -> CompactDecodeError x1_aNtQ)
      ( \x_aNtR ->
          case x_aNtR of
            CompactDecodeError y1_aNtS -> Right y1_aNtS
            _ -> Left x_aNtR
      )
  _JSONDecodeError =
    prism
      (\x1_aNtT -> JSONDecodeError x1_aNtT)
      ( \x_aNtU ->
          case x_aNtU of
            JSONDecodeError y1_aNtV -> Right y1_aNtV
            _ -> Left x_aNtU
      )
  _NoUsableKeys =
    prism
      (\() -> NoUsableKeys)
      ( \x_aNtW ->
          case x_aNtW of
            NoUsableKeys -> Right ()
            _ -> Left x_aNtW
      )
  _JWSCritUnprotected =
    prism
      (\() -> JWSCritUnprotected)
      ( \x_aNtX ->
          case x_aNtX of
            JWSCritUnprotected -> Right ()
            _ -> Left x_aNtX
      )
  _JWSNoValidSignatures =
    prism
      (\() -> JWSNoValidSignatures)
      ( \x_aNtY ->
          case x_aNtY of
            JWSNoValidSignatures -> Right ()
            _ -> Left x_aNtY
      )
  _JWSInvalidSignature =
    prism
      (\() -> JWSInvalidSignature)
      ( \x_aNtZ ->
          case x_aNtZ of
            JWSInvalidSignature -> Right ()
            _ -> Left x_aNtZ
      )
  _JWSNoSignatures =
    prism
      (\() -> JWSNoSignatures)
      ( \x_aNu0 ->
          case x_aNu0 of
            JWSNoSignatures -> Right ()
            _ -> Left x_aNu0
      )

newtype JOSE e m a = JOSE (ExceptT e m a)

-- | Run the 'JOSE' computation.  Result is an @Either e a@
-- where @e@ is the error type (typically 'Error' or 'Crypto.JWT.JWTError')
runJOSE :: JOSE e m a -> m (Either e a)
runJOSE = runExceptT . (\(JOSE m) -> m)

-- | Get the inner 'ExceptT' value of the 'JOSE' computation.
-- Typically 'runJOSE' would be preferred, unless you specifically
-- need an 'ExceptT' value.
unwrapJOSE :: JOSE e m a -> ExceptT e m a
unwrapJOSE (JOSE m) = m


instance (Functor m) => Functor (JOSE e m) where
  fmap f (JOSE ma) = JOSE (fmap f ma)

instance (Monad m) => Applicative (JOSE e m) where
  pure = JOSE . pure
  JOSE mf <*> JOSE ma = JOSE (mf <*> ma)

instance (Monad m) => Monad (JOSE e m) where
  JOSE ma >>= f = JOSE (ma >>= unwrapJOSE . f)

instance MonadTrans (JOSE e) where
  lift = JOSE . lift

instance (Monad m) => MonadError e (JOSE e m) where
  throwError = JOSE . throwError
  catchError (JOSE m) handle = JOSE (catchError m (unwrapJOSE . handle))

instance (MonadIO m) => MonadIO (JOSE e m) where
  liftIO = JOSE . liftIO

instance (MonadRandom m) => MonadRandom (JOSE e m) where
    getRandomBytes = lift . getRandomBytes
