
rule Trojan_BAT_AsyncRAT_NYA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 25 06 6f 90 01 03 0a 25 18 6f 90 01 03 0a 25 18 6f 90 01 03 0a 25 6f 90 01 03 0a 0b 04 07 02 16 02 8e 69 6f 90 00 } //01 00 
		$a_01_1 = {47 15 02 08 09 00 00 00 00 fa 01 33 00 16 c4 00 01 00 00 00 2f 00 00 00 03 00 00 00 09 00 00 00 05 00 00 00 3a 00 00 00 0e 00 00 00 04 00 00 00 01 00 00 00 01 } //00 00 
	condition:
		any of ($a_*)
 
}