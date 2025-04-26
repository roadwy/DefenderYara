
rule Trojan_BAT_AsyncRAT_BE_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 13 2b 3e 00 11 0a 11 13 28 16 00 00 0a 13 07 11 07 11 13 58 13 07 11 07 11 05 11 13 28 06 00 00 06 13 07 11 07 28 17 00 00 0a 13 09 11 09 16 11 0a 11 13 1a 28 15 00 00 0a 00 00 11 13 1a 58 13 13 11 13 11 06 fe 05 13 14 11 14 2d b6 } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}