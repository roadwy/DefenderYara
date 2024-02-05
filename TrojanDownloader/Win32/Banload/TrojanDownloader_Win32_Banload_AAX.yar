
rule TrojanDownloader_Win32_Banload_AAX{
	meta:
		description = "TrojanDownloader:Win32/Banload.AAX,SIGNATURE_TYPE_PEHSTR_EXT,2e 00 2e 00 0a 00 00 0a 00 "
		
	strings :
		$a_00_0 = {ff 68 e8 03 00 00 e8 } //0a 00 
		$a_00_1 = {68 80 00 00 00 6a ec } //0a 00 
		$a_00_2 = {0b 41 32 32 32 71 ac a3 9d ff cb ca c9 ff d6 d6 } //0a 00 
		$a_00_3 = {b2 a3 ff ff ee e4 ff fb e8 dc ff 6c 55 3e ff 25 24 24 29 18 18 17 1a 00 } //05 00 
		$a_01_4 = {54 46 72 6d 44 77 50 72 67 72 } //01 00 
		$a_01_5 = {44 2e 77 2e 50 2e 72 2e 67 2e 72 2e } //05 00 
		$a_01_6 = {54 46 72 6d 53 74 72 74 44 77 6e } //01 00 
		$a_01_7 = {53 2e 74 2e 72 2e 74 2e 44 2e 77 2e 6e 2e } //05 00 
		$a_01_8 = {54 66 72 50 6c 69 74 } //01 00 
		$a_01_9 = {50 6c 69 74 } //00 00 
	condition:
		any of ($a_*)
 
}