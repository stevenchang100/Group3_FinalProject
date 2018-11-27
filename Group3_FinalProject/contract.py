#!/usr/bin/python3

#contract just calculates the total amount of coins on the blockchain
#ONLY COPY THE CODE

i = 0
	
for wallet in blockchain.wallets:
	i = i + blockchain.wallets[wallet]['balance']

output = {
	'Total Coins': i
} 



