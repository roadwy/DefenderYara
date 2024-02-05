
rule TrojanDownloader_Win32_Banload_ANF{
	meta:
		description = "TrojanDownloader:Win32/Banload.ANF,SIGNATURE_TYPE_PEHSTR_EXT,ffffff96 00 ffffff82 00 0a 00 00 64 00 "
		
	strings :
		$a_01_0 = {64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f 37 36 37 32 34 34 35 32 } //0a 00 
		$a_01_1 = {31 69 74 61 73 2e 67 69 66 } //0a 00 
		$a_01_2 = {32 73 61 6e 74 61 2e 67 69 66 } //0a 00 
		$a_01_3 = {33 70 6c 6f 67 69 2e 67 69 66 } //0a 00 
		$a_01_4 = {34 70 65 67 61 76 62 2e 67 69 66 } //0a 00 
		$a_01_5 = {35 63 78 65 72 74 2e 67 69 66 } //0a 00 
		$a_01_6 = {36 6d 73 6e 7a 2e 67 69 66 } //0a 00 
		$a_01_7 = {37 7a 74 65 63 2e 67 69 66 } //1e 00 
		$a_01_8 = {77 69 6e 64 65 6c 65 74 65 2e 63 70 6c } //14 00 
		$a_01_9 = {62 6c 6f 67 2e 70 68 70 3f 70 6f 73 74 3d 31 30 31 35 30 34 30 38 34 38 38 39 36 32 31 33 31 } //00 00 
	condition:
		any of ($a_*)
 
}