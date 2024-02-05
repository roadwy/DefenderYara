
rule TrojanDownloader_Win32_Banload_ZFM_bit{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZFM!bit,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 4c 6f 63 61 6c 65 73 } //03 00 
		$a_01_1 = {72 65 6d 61 6e 73 6f 68 6f 74 65 6c 64 65 73 65 72 72 61 } //01 00 
		$a_03_2 = {62 6c 6f 67 90 02 30 77 70 2d 69 6e 63 6c 75 64 65 73 90 00 } //01 00 
		$a_01_3 = {00 70 68 70 00 } //01 00 
		$a_01_4 = {00 7a 69 70 00 } //01 00 
		$a_01_5 = {00 68 74 74 70 00 } //01 00 
		$a_01_6 = {00 6e 6f 74 69 66 79 00 } //01 00 
		$a_01_7 = {00 4a 55 4a 55 42 41 30 } //00 00 
	condition:
		any of ($a_*)
 
}