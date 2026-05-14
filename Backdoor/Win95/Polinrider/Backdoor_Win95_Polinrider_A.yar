
rule Backdoor_Win95_Polinrider_A{
	meta:
		description = "Backdoor:Win95/Polinrider.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 66 75 6c 6c 6e 6f 64 65 2e 6d 61 69 6e 6e 65 74 2e 61 70 74 6f 73 6c 61 62 73 2e 63 6f 6d 2f 76 31 2f 61 63 63 6f 75 6e 74 73 2f } //1 https://fullnode.mainnet.aptoslabs.com/v1/accounts/
		$a_01_1 = {2f 74 72 61 6e 73 61 63 74 69 6f 6e 73 3f 6f 6e 6c 79 5f 63 6f 6e 66 69 72 6d 65 64 3d 74 72 75 65 26 6f 6e 6c 79 5f 66 72 6f 6d 3d 74 72 75 65 26 6c 69 6d 69 74 3d 31 } //1 /transactions?only_confirmed=true&only_from=true&limit=1
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 61 70 69 2e 74 72 6f 6e 67 72 69 64 2e 69 6f 2f 76 31 2f 61 63 63 6f 75 6e 74 73 2f } //1 https://api.trongrid.io/v1/accounts/
		$a_01_3 = {62 73 63 2d 72 70 63 2e 70 75 62 6c 69 63 6e 6f 64 65 2e 63 6f 6d } //1 bsc-rpc.publicnode.com
		$a_01_4 = {62 73 63 2d 64 61 74 61 73 65 65 64 2e 62 69 6e 61 6e 63 65 2e 6f 72 67 } //1 bsc-dataseed.binance.org
		$a_01_5 = {65 74 68 5f 67 65 74 54 72 61 6e 73 61 63 74 69 6f 6e 42 79 48 61 73 68 } //1 eth_getTransactionByHash
		$a_01_6 = {3d 7b 68 6f 73 74 6e 61 6d 65 3a } //1 ={hostname:
		$a_01_7 = {28 7b 6a 73 6f 6e 72 70 63 3a } //1 ({jsonrpc:
		$a_01_8 = {2c 69 64 3a 31 7d 29 3b 63 6f 6e 73 74 } //1 ,id:1});const
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=6
 
}