
rule TrojanDownloader_Win32_Mondow_A_bit{
	meta:
		description = "TrojanDownloader:Win32/Mondow.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 37 2e 34 35 36 37 37 37 38 39 2e 63 6f 6d 90 02 30 2e 65 78 65 90 00 } //01 00 
		$a_01_1 = {00 6b 73 61 66 65 74 72 61 79 2e 65 78 65 00 } //01 00 
		$a_01_2 = {00 73 63 76 68 6f 73 74 2e 65 78 65 00 } //01 00 
		$a_01_3 = {00 43 3a 5c 6d 6f 6f 6e 2e 65 78 65 00 } //01 00 
		$a_01_4 = {72 65 67 20 61 64 64 20 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 22 } //00 00 
	condition:
		any of ($a_*)
 
}