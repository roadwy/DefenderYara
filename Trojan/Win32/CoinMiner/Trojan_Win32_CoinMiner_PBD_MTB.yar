
rule Trojan_Win32_CoinMiner_PBD_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.PBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4d 13 8a 14 01 00 55 ff 8d 34 01 0f b6 4d ff 8a 1c 01 03 c8 88 1e 88 11 8a 1e 8b 4d f8 02 da 0f b6 d3 03 f9 8a 14 02 30 17 41 3b 4d 0c 89 4d f8 } //4
		$a_00_1 = {79 79 72 75 74 69 66 6e 76 63 } //2 yyrutifnvc
	condition:
		((#a_01_0  & 1)*4+(#a_00_1  & 1)*2) >=6
 
}