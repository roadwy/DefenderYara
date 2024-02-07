
rule Trojan_BAT_AsyncRAT_E_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {03 04 17 8d 90 01 01 00 00 01 0a 06 16 05 a2 06 28 90 01 02 00 0a 0e 04 04 16 8d 90 01 01 00 00 01 28 90 01 02 00 0a 0e 05 04 18 8d 90 01 01 00 00 01 0b 07 16 16 8d 90 01 01 00 00 01 a2 07 28 90 00 } //01 00 
		$a_01_1 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}