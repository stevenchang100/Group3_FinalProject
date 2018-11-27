#!/usr/bin/python3
import json
import copy
import time
import random
import hashlib
import os
import binascii
from flask import Flask, request, Response, render_template

app = Flask(__name__)


class Blockchain:

    def __init__(self):
        self.chain = []
        self.difficulty_target = 4
        self.wallets = {}
        self.mempool = {}
        #used to hold the messages and contracts before they are processed into the block
        self.mespool = {}
        self.conpool = {}

#NEW-----------------------------------------------------------------------------------------------------

    def create_wallet(self):

        wallet = {
            'public_key': binascii.b2a_hex(os.urandom(8)).decode('ascii'),
            'private_key': binascii.b2a_hex(os.urandom(8)).decode('ascii'),
            'balance' : 10.0
        }
        self.wallets[wallet['public_key']] = wallet
        return wallet


    def get_clean_wallets(self):
        clean_wallets = copy.deepcopy(blockchain.wallets)
        for wallet in clean_wallets:
            del clean_wallets[wallet]['private_key']
        return clean_wallets


    def create_transaction(self, request):
        
        try:

            transaction = {
                'time': int(time.time()),
                'from': request.args.get('from', type = str),
                'to': request.args.get('to', type = str),
                'amount': float(request.args.get('amount', type = float))
            }

            private_key = request.args.get('private_key', default = '', type = str)

            assert transaction['from'] and transaction['to'] and transaction['amount']
            assert private_key == self.wallets[transaction['from']]['private_key']
            assert not transaction['from'] == transaction['to'] and transaction['to'] in self.wallets
            assert transaction['amount'] > 0 and transaction['amount'] <= self.wallets[transaction['from']]['balance']

        except:
            return False

        transaction_id = self.hash_transaction(transaction)
        self.mempool[transaction_id] = transaction
        
        return transaction_id


    def hash_transaction(self, transaction):
        hashId = hashlib.sha256()
        hashId.update(repr(transaction).encode('utf-8'))
        return str(hashId.hexdigest())


    def choose_transactions_from_mempool(self):

        processed_transactions = {}

        while len(processed_transactions) < 10 and len(self.mempool) > 0:

            transaction_id = random.choice(list(self.mempool))
            transaction = copy.deepcopy(self.mempool[transaction_id])

            if transaction['amount'] <= self.wallets[transaction['from']]['balance']:

                self.wallets[transaction['from']]['balance'] -= transaction['amount']
                self.wallets[transaction['to']]['balance'] += transaction['amount']

                processed_transactions[transaction_id] = transaction 
            
            del self.mempool[transaction_id]

        return processed_transactions


    def calculate_merkle_root(self, transactions):

        if len(transactions) == 0:
            return None

        elif len(transactions) == 1:
            return transactions[0]
            
        else:

            new_transactions = []

            for i in range(0, len(transactions), 2):

                if len(transactions) > (i+1):
                    hashId = hashlib.sha256()
                    hashId.update(transactions[i].encode('utf-8') + transactions[i+1].encode('utf-8'))
                    new_transactions.append(str(hashId.hexdigest()))
                else:
                    new_transactions.append(transactions[i])

            return self.calculate_merkle_root(new_transactions)


    def check_merkle_root(self, block):
        if calculate_merkle_root(block['transactions']) == block['header']['merkle_root']:
            return True
        else:
            return False


#--------------------------------------------------------------------------------------------------------

    def hash_block_header(self, block):
        hashId = hashlib.sha256()
        hashId.update(repr(block['header']).encode('utf-8'))
        return str(hashId.hexdigest())


    def get_last_block(self):
        return self.chain[-1]


    def create_block(self):

        block = {
            'header' : {
                'block_number': len(self.chain),
                'block_time': int(time.time()),
                'block_nonce': None,
                'previous_block_hash': (None if len(self.chain) == 0 else self.get_last_block()['hash']),
                'merkle_root': None
            },
            'transactions' : {},
            'messages' : {},
            'contracts' : {},
            'hash' : None
        }

        return block


    def mine_block(self):

        block = self.create_block()
        block['transactions'] = self.choose_transactions_from_mempool()
        #these call the move functions to add the messages and contracts into the block
        block['messages'] = self.move_message_from_mespool()
        block['contracts'] = self.move_contract_from_conpool()
        block['header']['merkle_root'] = self.calculate_merkle_root(list(block['transactions'].keys()))

        while True:
            block['header']['block_nonce'] = str(binascii.b2a_hex(os.urandom(8)))
            block['hash'] = self.hash_block_header(block)

            if block['hash'][:self.difficulty_target] == '0' * self.difficulty_target:
                break

        self.chain.append(block)

        return block


    def check_chain(self):

        for block_number in reversed(range(len(self.chain))):

            current_block = self.chain[block_number]

            if not current_block['hash'] == self.hash_block_header(current_block):
                return False

            if block_number > 0 and not current_block['header']['previous_block_hash'] == self.chain[block_number - 1]['hash']:
                return False

            if not self.check_merkle_root(current_block):
                return False

        return True

#My ATTEMPTS_____________________________________________________________________________________________

#This function finds Transactions that are on the blockchain for a specific account and returns them
    def find_transactions(self, keyTo):
        
        keyToTransactions = {}

        for block_number in reversed(range(len(self.chain))):

            current_block = self.chain[block_number]

            for key in current_block['transactions'].keys():

                if current_block['transactions'][key]['to'] == keyTo:

                    keyTransactions = copy.deepcopy(current_block['transactions'][key])
                    keyToTransactions[key] = keyTransactions

        return keyToTransactions

#This function finds all messages for a certain account on the blockchain and returns them
    def find_messages(self, keyTo):
        i = 1
        keyToMessages = {}

        for block_number in reversed(range(len(self.chain))):

            current_block = self.chain[block_number]

            for key in current_block['messages'].keys():

                if current_block['messages'][key]['mTo'] == keyTo:

                    keyMessages = copy.deepcopy(current_block['messages'][key])
                    del keyMessages['gas']
                    keyToMessages[i] = keyMessages
                    i = i + 1

        return keyToMessages

#This function finds the output of a Contract and returns it to the proper account
    def find_contract_output(self,keyTo):
        i = 1
        keyToContracts = {}
        for block_number in reversed(range(len(self.chain))):

            current_block = self.chain[block_number]

            for key in current_block['contracts'].keys():

                if current_block['contracts'][key]['public_key'] == keyTo:

                    keyContracts = copy.deepcopy(current_block['contracts'][key])
                    del keyContracts['gas']
                    keyToContracts[i] = keyContracts
                    i = i + 1

        return keyToContracts

#This function is used to login to a wallet account page
    def login(self, request):
        try:
            public_key = request.args.get('public_key', default = '', type = str)
            private_key = request.args.get('private_key', default = '', type = str)

            assert public_key and private_key
            assert private_key == self.wallets[public_key]['private_key']
        
        except:
            return False
        
        return public_key

#This function creates Transactions for the login page and adds them to the mempool 
    def create_transaction_login(self, keyFrom, keyTo, keyAmount, keyPrivate):
        
        try:

            transaction = {
                'time': int(time.time()),
                'from': keyFrom,
                'to': keyTo,
                'amount': float(keyAmount)
            }

            private_key = keyPrivate

            assert transaction['from'] and transaction['to'] and transaction['amount']
            assert private_key == self.wallets[transaction['from']]['private_key']
            assert not transaction['from'] == transaction['to'] and transaction['to'] in self.wallets
            assert transaction['amount'] > 0 and transaction['amount'] <= self.wallets[transaction['from']]['balance']

        except:
            return False

        transaction_id = self.hash_transaction(transaction)
        self.mempool[transaction_id] = transaction
        
        return transaction_id

#This function creates messages and sends them into mespool
    def send_message(self, keyFrom, keyTo, keyMessage, keyPrivate, gas):

        try:
            message = {
                'mTime': int(time.time()),
                'mFrom': keyFrom,
                'mTo': keyTo,
                'Sent_Message': keyMessage,
                'gas': gas
            }

            
            private_key = keyPrivate
            assert message['mFrom'] and message['mTo'] and message['Sent_Message']
            assert private_key == self.wallets[message['mFrom']]['private_key']
            assert not message['mFrom'] == message['mTo'] and message['mTo'] in self.wallets
            assert gas > 0 and gas <= self.wallets[message['mFrom']]['balance']


        except:
            return False


        message_id = self.hash_transaction(message)
        self.mespool[message_id] = message

        return message_id

#This function creates the contracts and sends them into the conpool
    def create_contract(self, keyPublic, keyPrivate, keyContract, keyName, gas):

        try:
            contract = {
                'cTime': int(time.time()),
                'public_key': keyPublic,
                'contract_code': keyContract,
                'contract_name': keyName,
                'gas': gas,
                'Data': {}
            }

            private_key = keyPrivate
            assert contract['public_key'] and contract['contract_code'] and contract['contract_name']
            assert private_key == self.wallets[contract['public_key']]['private_key']
            assert gas > 0 and gas <= self.wallets[contract['public_key']]['balance']

        except:
            return False

        contract_id = self.hash_transaction(contract)
        self.conpool[contract_id] = contract

        return contract_id

#This function moves all of the current messages and sends them into the block current block
#it also subtracts the gas price from the senders wallet if they have enough
    def move_message_from_mespool(self):

        processed_messages = {}

        while len(self.mespool) > 0:

            message_id = list(self.mespool)[len(self.mespool) - 1]
            message = copy.deepcopy(self.mespool[message_id])

            if message['gas'] <= self.wallets[message['mFrom']]['balance']:

                self.wallets[message['mFrom']]['balance'] -= message['gas']

                processed_messages[message_id] = message
            
            del self.mespool[message_id]

        return processed_messages

#This function moves the contracts from the conpool into the current block and runs the code for them
#it also subtracts the gas from the users wallet
    def move_contract_from_conpool(self):

        processed_contracts = {}

        while len(self.conpool) > 0:

            contract_id = list(self.conpool)[len(self.conpool) - 1]
            contract = copy.deepcopy(self.conpool[contract_id])


            if contract['gas'] <= self.wallets[contract['public_key']]['balance']:

                self.wallets[contract['public_key']]['balance'] -= contract['gas']

                #namespace is used to collect the output dictionary from the executed code
                namespace = {}
                globalsParameter = {'__builtins__' : None}
                #runs the code of the contract
                exec(contract['contract_code'], globals(), namespace)
                contract['Data'] = namespace['output']

                #deletes the code from the contract afterwards in order to clean up the blocks
                del contract['contract_code']
                processed_contracts[contract_id] = contract 

            del self.conpool[contract_id]

        return processed_contracts


#This is the login page
#It calls the information of the current account and then renders a HTML page that will display the relevant information about their account
@app.route('/login', methods = ['GET'])
def login():
    
    try:
        login_success = blockchain.login(request)
        walletBalance = blockchain.wallets[login_success]['balance']
        keyTransactions = blockchain.find_transactions(login_success)
        keyMessages = blockchain.find_messages(login_success)
        keyContracts = blockchain.find_contract_output(login_success)

    except:
        pass

    if login_success:
        return render_template('Group3_Login.html', public_key=login_success, Balance=walletBalance, Transaction=json.dumps(keyTransactions), Messages=json.dumps(keyMessages).replace('}','}<br>'), Contracts=json.dumps(keyContracts).replace('}','}<br>'))

    else:
        return Response(json.dumps({'Error': 'Invalid LOGIN'}), status=400, mimetype='application/json')



#This is the url used to create transactions
#it takes input from the HTML page and sends it into the create_transaction_login function to create transactions
@app.route('/create_transaction_login', methods = ['POST'])
def create_transaction_login():

    keyFrom = request.form['from']
    keyTo = request.form['to']
    keyAmount = float(request.form['amount'])
    keyPrivate = request.form['private_key']

    transaction_id = blockchain.create_transaction_login(keyFrom,keyTo,keyAmount,keyPrivate)

    if transaction_id:
        return Response(json.dumps({'Result': transaction_id}), status=200, mimetype='application/json')
    else:
        return Response(json.dumps({'Error': 'Invalid transaction'}), status=400, mimetype='application/json')

#This is the url used to send messages
#It takes input from the HTML page and sends it into the send_message function to create messages
@app.route('/send_message', methods = ['POST'])
def send_message():

    keyFrom = request.form['mFrom']
    keyTo = request.form['mTo']
    keyMessage = request.form['Sent_Message']
    keyPrivate = request.form['private_key']
    gas = len(keyMessage) * 0.01

    message_id = blockchain.send_message(keyFrom,keyTo,keyMessage,keyPrivate,gas)

    if message_id:
        return Response(json.dumps({'Result': message_id}), status=200, mimetype='application/json')
    else:
        return Response(json.dumps({'Error': 'Invalid Message'}), status=400, mimetype='application/json')

#This is the url used to create Contracts
#It takes input from the HTML page and sends it into the create_contract function to create Contracts
@app.route('/create_contract', methods = ['POST'])
def create_contract():
    keyPublic = request.form['public_Key']
    keyPrivate = request.form['private_key']
    keyContract = request.form['Contract']
    keyName = request.form['Name']
    gas = len(keyContract) * 0.01


    contract_id = blockchain.create_contract(keyPublic,keyPrivate,keyContract,keyName,gas)

    if contract_id:
        return Response(json.dumps({'Result': contract_id}), status=200, mimetype='application/json')
    else:
        return Response(json.dumps({'Error': 'Invalid Contract'}), status=400, mimetype='application/json')








#NEW-----------------------------------------------------------------------------------------------------
@app.route('/create_wallet', methods = ['GET'])
def create_wallet():
    return Response(json.dumps(blockchain.create_wallet()), status=200, mimetype='application/json')


@app.route('/create_transaction', methods = ['GET'])
def create_transaction():

    transaction_id = blockchain.create_transaction(request)

    if transaction_id:
        return Response(json.dumps({'Result': transaction_id}), status=200, mimetype='application/json')
    else:
        return Response(json.dumps({'Error': 'Invalid transaction'}), status=400, mimetype='application/json')


@app.route('/show_balances', methods = ['GET'])
def show_wallet_balances():
    return Response(json.dumps(blockchain.get_clean_wallets()), status=200, mimetype='application/json')


@app.route('/show_mempool', methods = ['GET'])
def show_mempool():
    return Response(json.dumps(blockchain.mempool), status=200, mimetype='application/json')

#--------------------------------------------------------------------------------------------------------      


@app.route('/mine_block', methods = ['GET'])
def mine_block():
    block = blockchain.mine_block()
    return Response(json.dumps(block), status=200, mimetype='application/json')


@app.route('/check_blockchain', methods = ['GET'])
def check_blockchain():
    if blockchain.check_chain:
        return Response(json.dumps({'Result': 'OK'}), status=200, mimetype='application/json')
    else:
        return Response(json.dumps({'Result': 'Invalid blockchain'}), status=200, mimetype='application/json')


@app.route('/show_blocks', methods = ['GET'])
def show_blocks():
    return Response(json.dumps(blockchain.chain), status=200, mimetype='application/json')


@app.route('/show_block', methods = ['GET'])
def show_block():
    try:
        block_number = request.args.get('number', default = 0, type = int)
        block = blockchain.chain[block_number]
    except:
        return Response(json.dumps({'Error': 'Invalid block number'}), status=400, mimetype='application/json')

    return Response(json.dumps(block), status=200, mimetype='application/json')


#--------------------------------------------------------------------------------------------------------


blockchain = Blockchain()
app.run(host = '127.0.0.1', port = 8080)
