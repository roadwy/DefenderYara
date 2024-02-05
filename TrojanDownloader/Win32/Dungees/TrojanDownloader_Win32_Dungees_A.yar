
rule TrojanDownloader_Win32_Dungees_A{
	meta:
		description = "TrojanDownloader:Win32/Dungees.A,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 ff d7 8d 44 00 02 50 8b 45 e4 03 45 f8 53 50 e8 d0 fe ff ff 56 68 80 00 00 00 6a 02 56 6a 02 68 00 00 00 40 ff 75 fc } //0a 00 
		$a_02_1 = {6a 03 56 56 68 bb 01 00 00 ff 34 85 00 30 00 04 ff 75 e4 ff 15 90 01 04 8b f8 3b fe 90 00 } //01 00 
		$a_00_2 = {2f 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_00_3 = {2f 00 70 00 6f 00 72 00 74 00 72 00 61 00 69 00 74 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}