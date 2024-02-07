
rule Trojan_BAT_Remcos_RQ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_2 = {5f 6f 6b 71 77 64 6f 71 77 6b 6f 64 71 77 } //01 00  _okqwdoqwkodqw
		$a_01_3 = {24 65 37 37 37 35 31 38 37 2d 36 65 65 65 2d 34 61 64 33 2d 39 39 63 64 2d 30 34 65 30 61 35 39 62 37 39 64 64 } //01 00  $e7775187-6eee-4ad3-99cd-04e0a59b79dd
		$a_01_4 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 } //00 00  System.Security
	condition:
		any of ($a_*)
 
}