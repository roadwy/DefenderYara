
rule Trojan_BAT_Lazy_NZ_MTB{
	meta:
		description = "Trojan:BAT/Lazy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 6d 00 00 0a 0b 07 28 90 01 01 00 00 0a 02 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0c 73 90 01 01 00 00 0a 0d 08 8e 69 17 da 13 04 16 13 05 2b 1f 90 00 } //01 00 
		$a_01_1 = {57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 5f 00 52 00 65 00 63 00 75 00 72 00 73 00 69 00 76 00 65 00 46 00 6f 00 72 00 6d 00 43 00 72 00 65 00 61 00 74 00 65 00 } //01 00  WinForms_RecursiveFormCreate
		$a_01_2 = {57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 5f 00 53 00 65 00 65 00 49 00 6e 00 6e 00 65 00 72 00 45 00 78 00 63 00 65 00 70 00 74 00 69 00 6f 00 6e 00 } //01 00  WinForms_SeeInnerException
		$a_01_3 = {6f 00 6e 00 6c 00 79 00 6f 00 6e 00 65 00 5f 00 75 00 70 00 64 00 61 00 74 00 65 00 72 00 } //01 00  onlyone_updater
		$a_01_4 = {42 00 6c 00 6f 00 67 00 5f 00 4b 00 65 00 79 00 77 00 6f 00 72 00 64 00 2e 00 65 00 78 00 65 00 } //00 00  Blog_Keyword.exe
	condition:
		any of ($a_*)
 
}