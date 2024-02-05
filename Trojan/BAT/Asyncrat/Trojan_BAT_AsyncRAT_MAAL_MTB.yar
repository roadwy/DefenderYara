
rule Trojan_BAT_AsyncRAT_MAAL_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MAAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 11 04 06 11 04 1e 5a 1e 6f 90 01 01 00 00 0a 18 28 90 01 01 00 00 0a 9c 11 04 17 58 13 04 00 17 13 08 2b c8 90 00 } //01 00 
		$a_01_1 = {02 72 40 02 00 70 72 01 00 00 70 28 } //00 00 
	condition:
		any of ($a_*)
 
}