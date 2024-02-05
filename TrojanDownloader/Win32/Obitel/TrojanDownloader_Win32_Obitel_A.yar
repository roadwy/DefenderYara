
rule TrojanDownloader_Win32_Obitel_A{
	meta:
		description = "TrojanDownloader:Win32/Obitel.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {66 69 78 61 73 65 72 76 65 72 2e 72 75 } //01 00 
		$a_00_1 = {6c 64 72 32 2f 67 61 74 65 2e 70 68 70 } //01 00 
		$a_00_2 = {68 61 73 68 3d } //01 00 
		$a_00_3 = {51 75 65 75 65 55 73 65 72 41 50 43 } //01 00 
		$a_00_4 = {75 73 65 72 69 6e 69 2e 65 78 65 } //01 00 
		$a_03_5 = {53 55 56 57 33 ed 55 55 55 68 90 01 04 55 55 ff 15 90 01 02 40 00 8b 90 01 05 55 8b f0 56 68 90 01 04 ff d7 8b 90 01 05 55 68 ec 00 00 00 ff d3 55 56 68 90 01 04 ff d7 56 ff 15 90 01 02 40 00 6a 01 6a ff ff d3 5f 5e 5d 33 c0 5b c2 10 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}