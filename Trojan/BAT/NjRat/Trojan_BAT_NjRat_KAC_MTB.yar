
rule Trojan_BAT_NjRat_KAC_MTB{
	meta:
		description = "Trojan:BAT/NjRat.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 00 41 00 67 00 41 00 41 00 41 00 52 00 79 00 76 00 51 00 41 00 41 00 63 00 49 00 41 00 4a 00 41 00 41 00 41 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_2 = {49 6e 76 6f 6b 65 } //00 00  Invoke
	condition:
		any of ($a_*)
 
}