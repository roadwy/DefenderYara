
rule TrojanDownloader_Win32_Yemrok_A{
	meta:
		description = "TrojanDownloader:Win32/Yemrok.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 5c 00 2e 00 5c 00 66 00 75 00 63 00 6b 00 33 00 36 00 30 00 00 00 } //01 00 
		$a_01_1 = {5c 25 63 25 63 25 63 25 63 25 63 2e 65 78 65 00 } //01 00 
		$a_00_2 = {48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 5c 43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 } //01 00 
		$a_03_3 = {5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 90 01 02 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}