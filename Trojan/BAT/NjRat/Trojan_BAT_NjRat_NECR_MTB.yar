
rule Trojan_BAT_NjRat_NECR_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {11 37 11 36 fe 02 16 fe 01 13 3c 11 3c 3a 90 01 01 fc ff ff 28 90 01 01 00 00 0a 11 38 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 39 11 39 90 00 } //02 00 
		$a_01_1 = {48 69 64 65 4d 6f 64 75 6c 65 4e 61 6d 65 41 74 74 72 69 62 75 74 65 } //02 00  HideModuleNameAttribute
		$a_01_2 = {5f 5f 45 4e 43 41 64 64 54 6f 4c 69 73 74 } //02 00  __ENCAddToList
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}