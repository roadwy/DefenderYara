
rule TrojanDownloader_Win32_Banload_ZEN{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZEN,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6f 77 6e 6c 6f 61 64 20 6c 69 6e 6b 20 3a 00 } //01 00 
		$a_01_1 = {42 61 7a 61 61 72 20 4c 69 6e 6b 20 3a 00 } //01 00 
		$a_01_2 = {74 65 78 74 69 69 6e 66 6f 00 } //01 00 
		$a_01_3 = {62 61 7a 61 72 20 66 75 63 6b 65 72 00 } //00 00 
		$a_00_4 = {5d 04 00 } //00 f5 
	condition:
		any of ($a_*)
 
}