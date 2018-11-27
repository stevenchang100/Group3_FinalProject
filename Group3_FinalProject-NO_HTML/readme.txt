How to run the code

first create a wallet:
http://127.0.0.1:8080/create_wallet

then enter the login page by using the public and private keys of the wallet and inputing them
next to the =:
http://127.0.0.1:8080/login?public_key=&private_key=

Now you that you are on the login page you can input public and private keys of wallets to
send transactions and messages, or to run Contracts.

For transactions and messages:
From = public_key of the sender
To = public_key of the recipient
private_key = the private key of the sender

For Contracts:
the Public and Private keys are yours.

to input code make sure its formatted correctly with tabs instead of spaces.
make sure that the data you want is inputed into a output dictionary.

the contract.py is just a sample contract, copy and paste it into the contracts text box
exclude the header (#!/usr/bin/python3)
