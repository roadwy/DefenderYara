
rule Trojan_AndroidOS_Gigabud_C{
	meta:
		description = "Trojan:AndroidOS/Gigabud.C,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 72 69 74 65 56 69 64 65 6f 55 72 6c } //01 00  writeVideoUrl
		$a_01_1 = {78 2f 75 73 65 72 2d 62 61 6e 6b 2d 70 77 64 } //01 00  x/user-bank-pwd
		$a_01_2 = {73 74 61 72 74 55 70 6c 6f 61 64 53 63 72 65 65 6e 52 65 63 6f 72 64 } //01 00  startUploadScreenRecord
		$a_01_3 = {69 73 48 61 76 65 41 63 63 65 73 73 69 62 69 6c 69 74 79 } //00 00  isHaveAccessibility
	condition:
		any of ($a_*)
 
}