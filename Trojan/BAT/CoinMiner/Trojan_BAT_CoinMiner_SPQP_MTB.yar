
rule Trojan_BAT_CoinMiner_SPQP_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.SPQP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e ce 07 00 04 7e cf 07 00 04 7e d0 07 00 04 61 7e d1 07 00 04 40 0d 00 00 00 7e 43 00 00 04 13 16 7e d2 07 00 04 58 00 6a 58 13 05 11 04 7e 45 00 00 04 13 17 7e d3 07 00 04 7e d4 07 00 04 7e d5 07 00 04 61 7e d6 07 00 04 40 0d 00 00 00 7e 43 00 00 04 13 17 7e d7 07 00 04 58 00 6f ?? ?? ?? 0a 11 05 28 ?? ?? ?? 0a 11 06 28 ?? ?? ?? 0a 3a 82 ff ff ff } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}
rule Trojan_BAT_CoinMiner_SPQP_MTB_2{
	meta:
		description = "Trojan:BAT/CoinMiner.SPQP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 03 2d 18 07 06 28 ?? ?? ?? 0a 72 cb 09 00 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 2b 16 07 06 28 ?? ?? ?? 0a 72 cb 09 00 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 17 73 34 00 00 0a 0d 09 02 16 02 8e 69 } //10
		$a_81_1 = {70 68 6e 69 70 68 70 63 73 69 76 6a 74 79 79 63 67 63 6c 6a 66 70 68 61 } //2 phniphpcsivjtyycgcljfpha
		$a_01_2 = {65 00 76 00 62 00 61 00 70 00 7a 00 68 00 6f 00 6e 00 75 00 77 00 75 00 68 00 69 00 65 00 75 00 } //2 evbapzhonuwuhieu
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}