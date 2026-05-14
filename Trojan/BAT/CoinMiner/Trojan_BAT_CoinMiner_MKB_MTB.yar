
rule Trojan_BAT_CoinMiner_MKB_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 11 06 6f 2b 00 00 0a 06 06 11 04 94 06 08 94 58 20 00 01 00 00 5d 94 61 d1 6f 2d 00 00 0a 26 00 11 06 17 58 13 06 11 06 03 6f 2a 00 00 0a fe 04 13 08 11 08 2d 9d } //25
		$a_01_1 = {08 06 07 94 58 02 07 02 6f 2a 00 00 0a 5d 6f 2b 00 00 0a 58 20 00 01 00 00 5d 0c 06 07 94 0d 06 07 06 08 94 9e 06 08 09 9e } //10
	condition:
		((#a_01_0  & 1)*25+(#a_01_1  & 1)*10) >=35
 
}