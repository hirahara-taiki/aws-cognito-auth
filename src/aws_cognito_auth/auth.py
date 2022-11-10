import json
import os
from typing import Optional
from dataclasses import dataclass
from getpass import getpass
import urllib.parse
import urllib.request
from configparser import ConfigParser
from datetime import datetime, timedelta
import boto3
import jwt
import qrcode
from tzlocal import get_localzone


@dataclass
class AuthenticationResult:
    """AuthenticationResult from Cognito user pool
    """
    AccessToken: str
    "str: access token. Expires in 60 minutes by default"
    IdToken: str
    "str: id token. Expires in 60 minutes by default"
    RefreshToken: str
    "str: refresh token. Expires in 30 days by default"
    TokenType: str
    "str: token type"
    Expiration: datetime
    "datetime: expiration date of access token and id token"

    @property
    def Expired(self) -> bool:
        "bool: Returns True if expired"
        return self.Expiration < datetime.now(get_localzone())

    @property
    def ExpiresSoon(self) -> bool:
        "bool: Returns True if expires within 5 minutes"
        return self.Expiration - timedelta(minutes=5) < datetime.now(get_localzone())

    def dump(self, profile: str):
        """dump arguments to ``~/.aws/cognito``

        Args:
            profile (str): name of aws profile
        """
        directory = os.path.join(os.path.expanduser("~"), ".aws")
        path = os.path.join(directory, "cognito")
        if not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)

        config = ConfigParser()
        if os.path.isfile(path):
            config.read(path)

        config[profile] = {
            "access_token": self.AccessToken,
            "id_token": self.IdToken,
            "refresh_token": self.RefreshToken,
            "token_type": self.TokenType,
            "expiration": self.Expiration.timestamp(),
        }

        with open(path, "w", encoding="utf8") as f:
            config.write(f, space_around_delimiters=False)

    @classmethod
    def delete(cls, profile: str):
        """delete profile from ``~/.aws/cognito``

        Args:
            profile (str): name of aws profile
        """
        directory = os.path.join(os.path.expanduser("~"), ".aws")
        path = os.path.join(directory, "cognito")
        if not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)

        config = ConfigParser()
        if os.path.isfile(path):
            config.read(path)

        config.pop(profile, {})

        with open(path, "w", encoding="utf8") as f:
            config.write(f, space_around_delimiters=False)


    @classmethod
    def load(cls, profile: str) -> "AuthenticationResult":
        """load arguments from ``~/.aws/cognito``

        Args:
            profile (str): name of aws profile

        Raises:
            FileNotFoundError: ``~/.aws/cognito`` is not found
            FileNotFoundError: profile is not found

        Returns:
            AuthenticationResult:
        """
        path = os.path.join(os.path.expanduser("~"), ".aws", "cognito")
        if not os.path.isfile(path):
            raise FileNotFoundError(path)

        config = ConfigParser()
        config.read(path)

        if not profile in config:
            raise FileNotFoundError(f"profile: {profile}")
        
        info = config[profile]
        return AuthenticationResult(
            info["access_token"],
            info["id_token"],
            info["refresh_token"],
            info["token_type"],
            datetime.fromtimestamp(float(info["expiration"]), get_localzone()),
        )


@dataclass
class Credentials:
    "aws credentials from cognito identity pool"
    AccessKeyId: str
    "str: access key id. Expires in 60 minutes by default"
    SecretKey: str
    "str: secret key. Expires in 60 minutes by default"
    SessionToken: str
    "str: session token. Expires in 60 minutes by default"
    Expiration: datetime
    "datetime: expiration date"

    @property
    def Expired(self) -> bool:
        "bool: Returns True if expired"
        return self.Expiration < datetime.now(get_localzone())

    @property
    def ExpiresSoon(self) -> bool:
        "bool: Returns True if expires within 5 minutes"
        return self.Expiration - timedelta(minutes=5) < datetime.now(get_localzone())

    def dump(self, profile: str):
        """dump arguments to ``~/.aws/credentials``

        Args:
            profile (str): name of aws profile
        """
        directory = os.path.join(os.path.expanduser("~"), ".aws")
        path = os.path.join(directory, "credentials")
        if not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)

        config = ConfigParser()
        if os.path.isfile(path):
            config.read(path)

        config[profile] = {
            "aws_access_key_id": self.AccessKeyId,
            "aws_secret_access_key": self.SecretKey,
            "aws_session_token": self.SessionToken,
            "expiration": self.Expiration.timestamp(),
        }

        with open(path, "w", encoding="utf8") as f:
            config.write(f, space_around_delimiters=False)

    @classmethod
    def delete(cls, profile: str):
        """delete profile from ``~/.aws/credentials``

        Args:
            profile (str): name of aws profile
        """
        directory = os.path.join(os.path.expanduser("~"), ".aws")
        path = os.path.join(directory, "credentials")
        if not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)

        config = ConfigParser()
        if os.path.isfile(path):
            config.read(path)

        config.pop(profile, {})

        with open(path, "w", encoding="utf8") as f:
            config.write(f, space_around_delimiters=False)

    @classmethod
    def load(cls, profile: str) -> "Credentials":
        """load arguments from ``~/.aws/credentials``

        Args:
            profile (str): name of aws profile

        Raises:
            FileNotFoundError: ``~/.aws/credentials`` is not found
            FileNotFoundError: profile is not found

        Returns:
            Credentials:
        """
        path = os.path.join(os.path.expanduser("~"), ".aws", "credentials")
        if not os.path.isfile(path):
            raise FileNotFoundError(path)

        config = ConfigParser()
        config.read(path)

        if not profile in config:
            raise FileNotFoundError(f"profile: {profile}")
        
        info = config[profile]
        return Credentials(
            info["aws_access_key_id"],
            info["aws_secret_access_key"],
            info["aws_session_token"],
            datetime.fromtimestamp(float(info["expiration"]), get_localzone()),
        )


class CognitoAuthenticator:
    def __init__(
            self,
            profile: str,
            email: Optional[str] = None,
            username: Optional[str] = None,
            region: Optional[str] = None,
            user_pool_id: Optional[str] = None,
            client_id: Optional[str] = None,
            identity_pool_id: Optional[str] = None,
    ):
        """Manage authentication

        Unspecified arguments are read from ``~/.aws/config`` based on "profile".
        If they are not specified even in this file, an error will occur.

        Args:
            profile (str): name of AWS profile
            email (Optional[str], optional): user email. Defaults to None.
            username (Optional[str], optional): user name. If not set, it will be the same as email. Defaults to None.
            region (Optional[str], optional): region name of Cognito User pool and Cognito identity pool. Defaults to None.
            user_pool_id (Optional[str], optional): Cognito user pool id. Defaults to None.
            client_id (Optional[str], optional): client app id of Cognito user pool. Defaults to None.
            identity_pool_id (Optional[str], optional): Cognito identity pool id. Defaults to None.
        """
        self.profile = profile

        self._authentication_result: Optional[AuthenticationResult] = None
        self._identity_id: Optional[str] = None
        self._credentials: Optional[Credentials] = None

        try:
            self._authentication_result = AuthenticationResult.load(profile)
        except:
            pass

        try:
            self._credentials = Credentials.load(profile)
        except:
            pass

        config = ConfigParser()
        directory = os.path.join(os.path.expanduser("~"), ".aws")
        path = os.path.join(directory, "config")
        if not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)
        if os.path.isfile(path):
            config.read(path)
        key = profile if profile == "default" else f"profile {profile}"
        if key not in config:
            config[key] = {}

        config[key]["output"] = "json"

        if region:
            config[key]["region"] = region
        else:
            region = config[key]["region"]

        if email:
            config[key]["cognito_user_email"] = email
        else:
            email = config[key]["cognito_user_email"]

        if username:
            config[key]["cognito_user_name"] = username
        elif "cognito_user_name" in config[key]:
            username = config[key]["cognito_user_name"]
        else:
            username = email
            config[key]["cognito_user_name"] = username

        if user_pool_id:
            config[key]["cognito_user_pool_id"] = user_pool_id
        else:
            user_pool_id = config[key]["cognito_user_pool_id"]

        if client_id:
            config[key]["cognito_user_pool_client_id"] = client_id
        else:
            client_id = config[key]["cognito_user_pool_client_id"]

        if identity_pool_id:
            config[key]["cognito_identity_pool_id"] = identity_pool_id
        else:
            identity_pool_id = config[key]["cognito_identity_pool_id"]

        self.email = email
        self.username = username
        self.region = region
        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.identity_pool_id = identity_pool_id

        with open(path, "w", encoding="utf8") as f:
            config.write(f, space_around_delimiters=False)

    def sign_up(self, password: Optional[str] = None):
        """sign up to cognito user pool.

        Args:
            password (str, optional): Your password. If not specified, you will be asked interactively. Default to None.

        Example:

            usage::

                >>> cognito = CognitoAuthenticator("your-profile")
                >>> cognito.sign_up()
                PASSWORD: 
        """
        if not password:
            password = getpass("PASSWORD: ")

        client = boto3.Session(region_name=self.region).client("cognito-idp")
        client.sign_up(
            ClientId=self.client_id,
            Username=self.username,
            Password=password,
            UserAttributes=[{"Name": "email", "Value": self.email}]
        )

    @classmethod
    def delete_credentials(cls, profile: str):
        """Remove the credentials corresponding to ``profile`` from ``~/.aws``.

        Args:
            profile (str): name of AWS profile
        """
        AuthenticationResult.delete(profile)
        Credentials.delete(profile)

    def resend_confirmation_code(self):
        """Resend confirmation code when sign-up fails.
        """
        client = boto3.Session(region_name=self.region).client("cognito-idp")
        client.resend_confirmation_code(ClientId=self.client_id, Username=self.username)

    def confirm_sign_up(self, code: Optional[str] = None):
        """Confirm sign-up. Must be done before signing in.

        Args:
            code (str, optional): confirmation code sent to email
        
        Example:

            usage::

                >>> cognito = CognitoAuthenticator("your-profile")
                >>> cognito.confirm_sign_up("012345")
        """
        client = boto3.Session(region_name=self.region).client("cognito-idp")
        if not code:
            code = input("Confirmation Code: ")
        client.confirm_sign_up(
            ClientId=self.client_id,
            Username=self.username,
            ConfirmationCode=code,
        )

    def forgot_password(self):
        """Reset your password when you forget it.

        Example:

            usage::

                >>> cognito = CognitoAuthenticator("your-profile")
                >>> cognito.forgot_password()
        """
        client = boto3.Session(region_name=self.region).client("cognito-idp")
        response = client.forgot_password(ClientId=self.client_id, Username=self.username)

    def confirm_forgot_password(self, code: Optional[str] = None, password: Optional[str] = None):
        """Confirm password change

        Args:
            code (Optional[str], optional): confirmation code. Defaults to None.
            password (Optional[str], optional): new password. Defaults to None.
        """
        client = boto3.Session(region_name=self.region).client("cognito-idp")
        if not code:
            code = input("Confirmation Code: ")
        if not password:
            password = getpass("Password: ")
        response = client.confirm_forgot_password(
            ClientId=self.client_id,
            ConfirmationCode=code,
            Username=self.username,
            Password=password,
        )

    def change_password(self, previous_password: Optional[str] = None, proposed_password: Optional[str] = None):
        """Change password. You must sign in.

        Example:

            usage::

                >>> cognito = CognitoAuthenticator("your-profile")
                >>> cognito.change_password()
                Previous Password:
                New Password:
        """
        client = boto3.Session(region_name=self.region).client("cognito-idp")
        if not previous_password:
            previous_password = getpass("Previous Password: ")
        if not proposed_password:
            proposed_password = getpass("New Password: ")
        client.change_password(
            PreviousPassword=previous_password,
            ProposedPassword=proposed_password,
            AccessToken=self.authentication_result.AccessToken,
        )

    def setup_software_mfa(self, issuer: str):
        """Set up MFA with software tokens.

        Args:
            issuer (str): service provider

        Example:

            usage::

                >>> cognito = CognitoAuthenticator("your-profile")
                >>> cognito.setup_software_mfa("your-app")
                User Code: 012345 # Scan the QR code with an app such as GoogleAuthenticator to obtain the code for authentication
        """
        client = boto3.Session(
            self.credentials.AccessKeyId,
            self.credentials.SecretKey,
            self.credentials.SessionToken,
            self.region,
        ).client("cognito-idp")
        response = client.associate_software_token(AccessToken=self.authentication_result.AccessToken)

        access_token_payload = jwt.decode(self.authentication_result.AccessToken, options={"verify_signature": False})
        account_name = access_token_payload['username']

        secret_code = response["SecretCode"]
        label_str = urllib.parse.quote(account_name, safe='')
        parameters = 'secret=' +  secret_code + '&issuer=' + issuer

        qrcode_str = 'otpauth://totp/' + label_str + '?' + parameters
        qr = qrcode.QRCode(box_size=10, border=2)
        qr.add_data(qrcode_str)
        qr.make(fit=True)
        img = qr.make_image()

        try:
            img.show()
        except:
            img.save("mfa.png")
            print("Load QRCode `mfa.png` with your auth app")

        client.verify_software_token(
            AccessToken=self.authentication_result.AccessToken,
            UserCode=input("User Code: ")
        )
        client.set_user_mfa_preference(
            SoftwareTokenMfaSettings={
                'Enabled': True,
                'PreferredMfa': True
            },
            AccessToken=self.authentication_result.AccessToken
        )

    def sign_in(self) -> AuthenticationResult:
        """sign in. Sign in again, even if the session has not expired.

        Raises:
            RuntimeError: unknown challenge

        Returns:
            AuthenticationResult:
        """
        client = boto3.Session(region_name=self.region).client("cognito-idp")
        response = client.initiate_auth(
            ClientId=self.client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": self.username, "PASSWORD": getpass("Password: ")},
        )
        if "ChallengeName" not in response:
            result = response["AuthenticationResult"]
        elif response["ChallengeName"] == "NEW_PASSWORD_REQUIRED":
            print("new password is required")
            _response = client.respond_to_auth_challenge(
                ClientId=self.client_id,
                ChallengeName="NEW_PASSWORD_REQUIRED",
                Session=response["Session"],
                ChallengeResponses={
                    "NEW_PASSWORD": getpass("NEW PASSWORD: "),
                    "USERNAME": self.username
                }
            )
            result = _response["AuthenticationResult"]
        elif response["ChallengeName"] == "SMS_MFA":
            print("sms mfa is required")
            _response = client.respond_to_auth_challenge(
                ClientId=self.client_id,
                ChallengeName="SMS_MFA",
                Session=response["Session"],
                ChallengeResponses={
                    "SMS_MFA_CODE": input("SMS MFA CODE: "),
                    "USERNAME": self.username
                    }
                )
            result = _response["AuthenticationResult"]
        elif response["ChallengeName"] == "SOFTWARE_TOKEN_MFA":
            print("software token mfa is required")
            _response = client.respond_to_auth_challenge(
                ClientId=self.client_id,
                ChallengeName="SOFTWARE_TOKEN_MFA",
                Session=response["Session"],
                ChallengeResponses={
                    "SOFTWARE_TOKEN_MFA_CODE": input("SOFTWARE TOKEN MFA CODE: "),
                    "USERNAME": self.username
                    }
                )
            result = _response["AuthenticationResult"]
        # elif response["ChallengeName"] == "MFA_SETUP":
        #     pass
        else:
            raise RuntimeError(f"This challenge is not implemented: {response['ChallengeName']}")

        result["Expiration"] = datetime.now(get_localzone()) + timedelta(seconds=result.pop("ExpiresIn"))
        self._authentication_result = AuthenticationResult(**result)
        self._authentication_result.dump(self.profile)
        return self._authentication_result

    @property
    def authentication_result(self) -> AuthenticationResult:
        "AuthenticationResult: authentication result from cognito user pool"
        if self._authentication_result is None:
            return self.sign_in()

        elif self._authentication_result.ExpiresSoon:
            print("refresh tokens")
            client = boto3.Session(region_name=self.region).client("cognito-idp")
            try:
                response = client.initiate_auth(
                    ClientId=self.client_id,
                    AuthFlow="REFRESH_TOKEN_AUTH",
                    AuthParameters={"REFRESH_TOKEN": self._authentication_result.RefreshToken},
                )
            except:
                return self.sign_in()
            result = response["AuthenticationResult"]
            result["Expiration"] = datetime.now(get_localzone()) + timedelta(seconds=result.pop("ExpiresIn"))
            self._authentication_result = AuthenticationResult(RefreshToken=self._authentication_result.RefreshToken, **result)
            self._authentication_result.dump(self.profile)

        return self._authentication_result

    @property
    def provider_name(self) -> str:
        "str: name of ID Provider"
        return f"cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}"

    @property
    def identity_id(self) -> str:
        "str: identity id from cognito user pool"
        if self._identity_id is None:
            client = boto3.Session(region_name=self.region).client("cognito-identity")
            response = client.get_id(
                IdentityPoolId = self.identity_pool_id,
                Logins = {self.provider_name: self.authentication_result.IdToken}
            )
            self._identity_id = response["IdentityId"]

        return self._identity_id

    @property
    def credentials(self) -> Credentials:
        "str: aws credentials of IAM role associated with cognito"
        if self._credentials is None or self._credentials.ExpiresSoon:
            client = boto3.Session(region_name=self.region).client("cognito-identity")
            response = client.get_credentials_for_identity(
                IdentityId=self.identity_id,
                Logins = {self.provider_name: self.authentication_result.IdToken}
            )
            self._credentials = Credentials(**response["Credentials"])
            self._credentials.dump(self.profile)
        return self._credentials

    @property
    def console_url(self) -> str:
        "str: URL to sign in to the AWS Management Console"
        json_formed_session = f"{{\"sessionId\":\"{self.credentials.AccessKeyId}\",\"sessionKey\":\"{self.credentials.SecretKey}\",\"sessionToken\":\"{self.credentials.SessionToken}\"}}"
        encoded_json_formed_session = urllib.parse.quote(json_formed_session).replace("=$", "").replace("=", "%").replace("\n", "")
        get_sign_in_token_url = f"https://signin.aws.amazon.com/federation?Action=getSigninToken&SessionType=json&Session={encoded_json_formed_session}"
        with urllib.request.urlopen(get_sign_in_token_url) as response:
            signin_token = json.loads(response.read().decode())["SigninToken"].replace("\\", "").replace("\"", "")

        encoded_issuer_url = urllib.parse.quote("https://example.com/").replace("=$", "").replace("=", "%").replace("\n", "")
        encoded_console_url = urllib.parse.quote("https://console.aws.amazon.com/").replace("=$", "").replace("=", "%").replace("\n", "")
        return f"https://signin.aws.amazon.com/federation?Action=login&Issuer={encoded_issuer_url}&Destination={encoded_console_url}&SigninToken={signin_token}"
