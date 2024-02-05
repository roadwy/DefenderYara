
rule PUA_Linux_CoinMiner_xmrig{
	meta:
		description = "PUA:Linux/CoinMiner!xmrig,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {67 69 74 68 75 62 2e 63 6f 6d 2f 78 6d 72 69 67 2f 78 6d 72 69 67 2f 72 65 6c 65 61 73 65 73 2f 64 6f 77 6e 6c 6f 61 64 } //00 00 
	condition:
		any of ($a_*)
 
}
rule PUA_Linux_CoinMiner_xmrig_2{
	meta:
		description = "PUA:Linux/CoinMiner!xmrig,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {34 36 51 42 75 6d 6f 76 57 79 34 64 4c 4a 34 52 38 77 71 38 4a 77 68 48 4b 57 4d 68 43 61 44 79 4e 44 45 7a 76 78 48 46 6d 41 48 6e 39 32 45 79 4b 72 74 74 71 36 4c 66 56 36 69 66 35 55 59 44 41 79 43 7a 68 33 65 67 57 58 4d 68 6e 66 4a 4a 72 45 68 57 6b 4d 7a 71 54 50 7a 47 7a 73 45 } //01 00 
		$a_00_1 = {34 34 45 73 70 47 69 76 69 50 64 65 5a 53 5a 79 58 31 72 33 52 39 52 68 70 47 43 6b 78 59 41 43 45 4b 55 77 62 41 34 47 70 36 63 56 43 7a 79 69 4e 65 42 32 31 53 54 57 59 73 4a 5a 59 5a 65 5a 74 36 33 4a 61 55 6e 38 43 56 78 44 65 57 57 47 73 33 66 36 58 4e 78 47 50 74 53 75 55 45 58 } //00 00 
	condition:
		any of ($a_*)
 
}