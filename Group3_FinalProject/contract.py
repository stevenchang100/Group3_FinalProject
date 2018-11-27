#!/usr/bin/python3


i = 0
	
for wallet in blockchain.wallets:
	i = i + blockchain.wallets[wallet]['balance']

output = {
	'Total Coins': i
} 



