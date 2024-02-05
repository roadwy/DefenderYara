
rule TrojanDownloader_Win32_Carberp_BU{
	meta:
		description = "TrojanDownloader:Win32/Carberp.BU,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 5f 42 54 5f 56 45 52 3a 90 02 0a 00 90 00 } //01 00 
		$a_01_1 = {45 53 54 52 5f 50 41 53 53 5f 00 } //02 00 
		$a_03_2 = {5f 44 4c 4c 5f 44 41 54 41 5f 90 02 10 4d 5a 90 00 } //03 00 
		$a_03_3 = {8e fe 1f 4b 90 03 01 01 e8 74 90 00 } //03 00 
		$a_01_4 = {68 f8 7f d6 aa 6a 02 6a 00 e8 } //03 00 
		$a_01_5 = {68 f8 7f d6 aa 6a 02 53 a4 89 5d f8 89 5d f4 89 5d f0 89 5d fc e8 } //01 00 
		$a_01_6 = {62 6b 69 2e 70 6c 75 67 } //01 00 
		$a_01_7 = {69 6e 73 74 61 6c 6c 62 6b } //00 00 
		$a_00_8 = {5d 04 00 00 7a 0d } //03 80 
	condition:
		any of ($a_*)
 
}