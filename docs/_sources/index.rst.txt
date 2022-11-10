.. aws-cognito-auth documentation master file, created by
   sphinx-quickstart on Sun Nov  6 11:35:21 2022.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to aws-cognito-auth's documentation!
============================================

.. toctree::
   :maxdepth: 2
   :caption: API

   aws_cognito_auth

How to use as CLI
=================

The API can be used programmatically or as a simple CLI tool.

First record Cognito information.

.. code-block:: bash

    aws-cognito-auth register --user-email whoami@example.com [--user-name whoami] --region ap-east-1 --user-pool-id <USER_POOL_ID> --client-id <CLIENT_ID> --identity-pool-id <IDENTITY_POOL_ID> <your-profile>


Sign up if you have not already done so.


.. code-block:: bash

    aws-cognito-auth signup <your-profile>


Two-step verification is available. Use an application such as GoogleAuthenticator to set it up.


.. code-block:: bash

    aws-cognito-auth enable-mfa <your-profile>


Obtain credentials for IAM roles. You can now use profile with awscli.


.. code-block:: bash

    aws-cognito-auth auth <your-profile>
    aws sts get-caller-identity --profile <your-profile>


You can also log in to the AWS Management Console.

.. code-block:: bash

   aws-cognito-auth console <your-profile>



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
