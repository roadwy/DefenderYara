
rule TrojanDownloader_Win32_Banload_JV{
	meta:
		description = "TrojanDownloader:Win32/Banload.JV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 72 72 6f 20 34 30 34 21 } //01 00 
		$a_01_1 = {73 79 73 74 65 6d 33 32 5c 69 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //01 00 
		$a_01_2 = {45 78 70 6c 6f 72 65 72 00 68 74 74 70 3a 2f 2f 6e 61 72 75 74 6f 32 30 30 39 2e } //00 00 
	condition:
		any of ($a_*)
 
}