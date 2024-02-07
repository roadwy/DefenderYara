
rule TrojanDropper_WinNT_Adwind_BE_MTB{
	meta:
		description = "TrojanDropper:WinNT/Adwind.BE!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 64 65 66 72 74 6c 72 69 62 2f 4d 64 63 70 63 67 65 6f 61 73 62 } //01 00  idefrtlrib/Mdcpcgeoasb
		$a_00_1 = {6d 6d 76 65 71 69 6b 6d 75 70 2e 6a 73 } //01 00  mmveqikmup.js
		$a_00_2 = {72 65 73 6f 75 72 63 65 73 2f 7a 6b 71 79 79 73 78 76 76 72 } //00 00  resources/zkqyysxvvr
	condition:
		any of ($a_*)
 
}