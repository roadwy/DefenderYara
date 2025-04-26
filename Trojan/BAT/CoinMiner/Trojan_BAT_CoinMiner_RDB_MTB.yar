
rule Trojan_BAT_CoinMiner_RDB_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6e 4c 6f 63 6b } //1 nLock
		$a_01_1 = {32 64 39 38 30 30 62 63 2d 32 38 31 35 2d 34 39 33 62 2d 38 38 66 35 2d 37 31 38 39 35 66 34 39 32 64 37 38 } //1 2d9800bc-2815-493b-88f5-71895f492d78
		$a_01_2 = {62 00 6b 00 78 00 76 00 59 00 32 00 73 00 6c 00 } //1 bkxvY2sl
		$a_01_3 = {50 00 75 00 62 00 6c 00 69 00 63 00 4b 00 65 00 79 00 54 00 6f 00 6b 00 65 00 6e 00 3d 00 } //1 PublicKeyToken=
		$a_01_4 = {44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 DESCryptoServiceProvider
		$a_01_5 = {44 65 66 6c 61 74 65 53 74 72 65 61 6d } //1 DeflateStream
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}