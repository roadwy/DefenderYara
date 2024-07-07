
rule Backdoor_Linux_CoinThief_A{
	meta:
		description = "Backdoor:Linux/CoinThief.A,SIGNATURE_TYPE_MACHOHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 61 66 61 72 69 45 78 74 65 6e 73 69 6f 6e 4d 6f 6e 69 74 6f 72 00 63 68 72 6f 6d 65 45 78 74 65 6e 73 69 6f 6e 4d 6f 6e 69 74 6f 72 } //2
		$a_01_1 = {66 73 36 33 34 38 39 32 33 6c 6f 63 6b 00 41 67 65 6e 74 } //2
		$a_01_2 = {2f 74 6d 70 2f 5f 61 67 6e 25 6c 75 } //2 /tmp/_agn%lu
		$a_01_3 = {69 73 42 69 74 63 6f 69 6e 51 74 49 6e 73 74 61 6c 6c 65 64 } //2 isBitcoinQtInstalled
		$a_01_4 = {2f 75 73 72 2f 62 69 6e 2f 75 6e 7a 69 70 00 2d 64 00 5f 5f 4d 41 43 4f 53 58 00 69 6e 73 74 61 6c 6c } //2 甯牳戯湩甯穮灩ⴀd彟䅍佃塓椀獮慴汬
		$a_01_5 = {50 4f 53 54 20 5c 2f 28 5b 5e 20 5d 2a 29 20 48 54 54 50 5c 2f 31 5c 2e 28 5b 30 31 5d 29 2e 2a 43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a 20 28 5b 30 2d 39 5d 2b 29 2e 2a 25 40 25 40 } //2 POST \/([^ ]*) HTTP\/1\.([01]).*Content-Length: ([0-9]+).*%@%@
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}