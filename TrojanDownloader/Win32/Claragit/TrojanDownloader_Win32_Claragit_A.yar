
rule TrojanDownloader_Win32_Claragit_A{
	meta:
		description = "TrojanDownloader:Win32/Claragit.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {6a 00 83 e1 03 6a 00 6a 00 68 90 01 04 f3 aa ff 15 90 01 04 8b f8 85 ff 74 48 8b 44 24 14 56 6a 00 68 00 00 00 80 90 00 } //02 00 
		$a_03_1 = {75 30 8d 44 24 04 50 ff 15 90 01 04 8b 54 24 00 8d 4c 24 04 50 51 6a 01 6a 00 90 00 } //01 00 
		$a_01_2 = {2e 63 6f 6d 2f 73 75 63 2e 70 68 70 } //01 00 
		$a_01_3 = {73 76 63 68 6f 73 74 77 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}