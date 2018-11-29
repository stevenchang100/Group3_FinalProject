#This contract is made to collect data about a public_key provided by the caller
#it will return any transaction sent to the public_key and contracts that they are the admin of
#Contracts were made so that the first time it is run it will initialize what data it needs
#and subsequent runs can then properly take in variables, calculate and return the values
#user need to know what to send and in what order and append it into the url
#ex: &var=1&var=2...
if contract['data']:
	keyToTransactions = {}
	for block_number in reversed(range(len(blockchain.chain))):

		current_block = blockchain.chain[block_number]

		for key in current_block['transactions'].keys():

			if current_block['transactions'][key]['to'] == contract['data']['public_key']:

				keyToTransactions[key] = current_block['transactions'][key]
				
	keyToContracts = []

	for contractKey in blockchain.contracts.keys():

		if blockchain.contracts[contractKey]['admin'] == contract['data']['public_key']:

			keyContracts = 'Contract Name: ' + blockchain.contracts[contractKey]['contract_name'] + ' contract_ID: ' + blockchain.contracts[contractKey]['public_key']

			keyToContracts.append(keyContracts)

	output = {
	'public_key': contract['data']['public_key'],
	'Transactions': keyToTransactions,
	'Contracts': keyToContracts
	}

	data = {
		'public_key': contract['data']['public_key']
	}
else:
	output = {
	'public_key': None,
	'Transactions': {},
	'Contracts': []
	}

	data = {
		'public_key': None
	}
