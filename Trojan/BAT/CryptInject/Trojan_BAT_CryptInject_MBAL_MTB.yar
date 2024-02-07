
rule Trojan_BAT_CryptInject_MBAL_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 00 51 00 44 00 66 00 4b 00 7a 00 4d 00 4b 00 62 00 6e 00 } //01 00  lQDfKzMKbn
		$a_01_1 = {34 00 34 00 34 00 34 00 43 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 74 00 78 00 74 00 } //01 00  4444Config.txt
		$a_01_2 = {30 00 62 00 68 00 4f 00 46 00 35 00 73 00 73 00 54 00 64 00 5f 00 77 00 65 00 77 00 44 00 46 00 49 00 } //01 00  0bhOF5ssTd_wewDFI
		$a_01_3 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 5c 00 49 00 6d 00 67 00 4e 00 61 00 6d 00 65 00 2e 00 70 00 6e 00 67 00 } //01 00  Downloads\ImgName.png
		$a_81_4 = {70 65 72 6d 75 6e 62 61 6e } //00 00  permunban
	condition:
		any of ($a_*)
 
}