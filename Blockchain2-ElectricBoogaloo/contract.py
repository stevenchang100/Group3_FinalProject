
if contract['data']:
	keyToTransactions = {}
	for block_number in reversed(range(len(blockchain.chain))):

		current_block = blockchain.chain[block_number]

		for key in current_block['transactions'].keys():

			if current_block['transactions'][key]['to'] == contract['data']['public_key']:

				keyTransactions = copy.deepcopy(current_block['transactions'][key])
				keyToTransactions[key] = keyTransactions
	keyToContracts = []

	for contractKey in blockchain.contracts.keys():

		if blockchain.contracts[contractKey]['admin'] == contract['data']['public_key']:

			keyContracts = blockchain.contracts[contractKey]['contract_name']
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
