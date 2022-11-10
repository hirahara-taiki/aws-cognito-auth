from argparse import ArgumentParser, Namespace
import sys
import subprocess
from . import __version__, CognitoAuthenticator

def main():
    """Entry point when the command is executed
    """
    parser = ArgumentParser(description='First, use the "register" command to store the information needed for authentication in a local file.')
    parser.add_argument("--version", "-v", action="store_true")
    subparsers = parser.add_subparsers()

    parser_register = subparsers.add_parser("register", help="register AWS profile to localfile")
    parser_register.add_argument("profile", type=str, help="name of AWS profile")
    parser_register.add_argument("--user-email", type=str, required=True, help="name of AWS profile")
    parser_register.add_argument("--user-name", type=str, required=False, default=None, help="name of AWS profile")
    parser_register.add_argument("--region", type=str, required=True, help="name of AWS profile")
    parser_register.add_argument("--user-pool-id", type=str, required=True, help="name of AWS profile")
    parser_register.add_argument("--client-id", type=str, required=True, help="name of AWS profile")
    parser_register.add_argument("--identity-pool-id", type=str, required=True, help="name of AWS profile")
    parser_register.set_defaults(handler=command_register)
    
    parser_signup = subparsers.add_parser("signup", help="sign-up to service")
    parser_signup.add_argument("profile", type=str, help="name of AWS profile")
    parser_signup.set_defaults(handler=command_signup)

    parser_re_signup = subparsers.add_parser("re-signup", help="resend confirmation code and retry sign-up confirmation")
    parser_re_signup.add_argument("profile", type=str, help="name of AWS profile")
    parser_re_signup.set_defaults(handler=command_re_signup)

    parser_delete_credentials_cache = subparsers.add_parser("delete-credentials-cache", help="delete cognito auth and aws credentials")
    parser_delete_credentials_cache.add_argument("profile", type=str, help="name of AWS profile")
    parser_delete_credentials_cache.set_defaults(handler=command_delete_credentials_cache)

    parser_enable_mfa = subparsers.add_parser("enable-mfa", help="register and enable software MFA")
    parser_enable_mfa.add_argument("profile", type=str, help="name of AWS profile")
    parser_enable_mfa.add_argument("--issuer", type=str, default="Cognito", required=False, help="issuer name")
    parser_enable_mfa.set_defaults(handler=command_enable_mfa)

    parser_forgot_password = subparsers.add_parser("forgot-password", help="reset your password when you forget it")
    parser_forgot_password.add_argument("profile", type=str, help="name of AWS profile")
    parser_forgot_password.set_defaults(handler=command_forgot_password)

    parser_change_password = subparsers.add_parser("change-password", help="change your password")
    parser_change_password.add_argument("profile", type=str, help="name of AWS profile")
    parser_change_password.set_defaults(handler=command_change_password)

    parser_auth = subparsers.add_parser("auth", help="get temporary credential information that can be used from AWS SDKs such as aws-cli")
    parser_auth.add_argument("profile", type=str, help="name of AWS profile")
    parser_auth.set_defaults(handler=command_auth)

    parser_console = subparsers.add_parser("console", help="log in to the AWS Management Console using temporary credentials")
    parser_console.add_argument("profile", type=str, help="name of AWS profile")
    parser_console.set_defaults(handler=command_console)

    args: Namespace = parser.parse_args()
    if hasattr(args, 'handler'):
        args.handler(args)
    else:
        if args.version:
            print(f"aws-cognito-auth: {__version__}")
        else:
            parser.print_help()

def command_register(args: Namespace):
    """save profile to ``~/.aws/config``

    Args:
        args (Namespace): command line arguments
    """
    CognitoAuthenticator(
        args.profile,
        args.user_email,
        args.user_name,
        args.region,
        args.user_pool_id,
        args.client_id,
        args.identity_pool_id,
    )

    print('First, complete "signup" if not already done.')
    print('To use two-step authentication, use the "enable-mfa" command.')
    print('To obtain temporary credentials and use the aws command, use the "auth" command.')
    print('To login to the AWS management console, use the "console" command.')

def command_signup(args: Namespace):
    """Sign up for the service. You must be registered in config beforehand with the "register" command.

    Args:
        args (Namespace): command line arguments
    """
    cognito = CognitoAuthenticator(args.profile)
    cognito.sign_up()
    print(
        'If you do not receive a confirmation code, '
        'interrupt with "Ctrl+C" and then '
        'use the re-signup command.'
    )
    cognito.confirm_sign_up()

    print('To use two-step authentication, use the "enable-mfa" command.')
    print('To obtain temporary credentials and use the aws command, use the "auth" command.')
    print('To login to the AWS management console, use the "console" command.')

def command_re_signup(args: Namespace):
    """Redo the verification process if you failed to obtain a verification code during sign-up.

    Args:
        args (Namespace): command line arguments
    """
    cognito = CognitoAuthenticator(args.profile)
    cognito.resend_confirmation_code()
    cognito.confirm_sign_up()

    print('To use two-step authentication, use the "enable-mfa" command.')
    print('To obtain temporary credentials and use the aws command, use the "auth" command.')
    print('To login to the AWS management console, use the "console" command.')

def command_delete_credentials_cache(args: Namespace):
    """delete profile from ``~/.aws/cognito`` and ``~/.aws/credentials``

    Args:
        args (Namespace): command line arguments
    """
    CognitoAuthenticator.delete_credentials(args.profile)

def command_enable_mfa(args: Namespace):
    """Enable two-step verification

    Args:
        args (Namespace): command line arguments
    """
    cognito = CognitoAuthenticator(args.profile)
    cognito.setup_software_mfa(args.issuer)

def command_forgot_password(args: Namespace):
    """Reset your password when you forget it.

    Args:
        args (Namespace): command line arguments
    """
    cognito = CognitoAuthenticator(args.profile)
    cognito.forgot_password()
    cognito.confirm_forgot_password()

def command_change_password(args: Namespace):
    """Change password

    Args:
        args (Namespace): command line arguments
    """
    cognito = CognitoAuthenticator(args.profile)
    cognito.change_password()

def command_auth(args: Namespace):
    """Retrieve your Cognito credentials and AWS credentials and store them in ``~/.aws/cognito`` and ``~/.aws/credentials`` respectively.

    Args:
        args (Namespace): command line arguments
    """
    cognito = CognitoAuthenticator(args.profile)
    cognito.credentials

def command_console(args: Namespace):
    """Open the AWS Management Console

    Args:
        args (Namespace): command line arguments
    """
    cognito = CognitoAuthenticator(args.profile)
    url = cognito.console_url

    if sys.platform == "win32":
        subprocess.run(f"rundll32.exe url.dll,FileProtocolHandler \"{url}\"", shell=True, encoding="utf8")
    else:
        subprocess.run(f"open \"{url}\"", shell=True)
