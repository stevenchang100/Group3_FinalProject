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
            'hash' : None
        }

        return block


    def mine_block(self):

        block = self.create_block()
        block['transactions'] = self.choose_transactions_from_mempool()
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
    def find_transactions(self, keyTo):
        i = 0
        keyToTransactions = {}

        for block_number in reversed(range(len(self.chain))):

            current_block = self.chain[block_number]

            for key, value in current_block['transactions']['transaction_id'].items():

                if current_block['transactions'][value]['to'] == keyTo:

                    keyTransactions = deepcopy.current_block['transactions'][vlaue]
                    keyToTransactions[value] = keyTransactions

            

        return keyToTransactions

    def login(self, request):
        try:
            public_key = request.args.get('public_key', default = '', type = str)
            private_key = request.args.get('private_key', default = '', type = str)

            assert public_key and private_key
            assert private_key == self.wallets[public_key]['private_key']
        
        except:
            return False
        
        return public_key


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


@app.route('/login', methods = ['GET'])
def login():
    

    login_success = blockchain.login(request)
    walletBalance = blockchain.wallets[login_success]['balance']
    keyTransactions = blockchain.find_transactions(login_success)

    if login_success:
        return render_template('Group3_Login.html', public_key=login_success, Balance=walletBalance, Transaction=json.dumps(keyTransactions))
    else:
        return Response(json.dumps({'Error': 'Invalid transaction'}), status=400, mimetype='application/json')




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
