
rule Trojan_BAT_AsyncRAT_NRT_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 09 00 00 06 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 28 90 01 03 06 0a 72 90 01 03 70 06 28 90 01 03 0a 72 90 01 03 70 28 90 01 03 0a 26 2a 90 00 } //01 00 
		$a_01_1 = {63 72 79 70 74 65 72 32 } //01 00 
		$a_01_2 = {72 00 6e 00 61 00 75 00 64 00 61 00 72 00 2a 00 61 00 74 00 32 00 } //00 00 
	condition:
		any of ($a_*)
 
}