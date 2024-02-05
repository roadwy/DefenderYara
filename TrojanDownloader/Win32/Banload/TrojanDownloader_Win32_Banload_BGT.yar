
rule TrojanDownloader_Win32_Banload_BGT{
	meta:
		description = "TrojanDownloader:Win32/Banload.BGT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {38 47 46 46 34 58 4c 42 37 57 48 4d } //01 00 
		$a_01_1 = {34 39 38 39 42 41 36 39 39 46 45 44 34 35 } //01 00 
		$a_03_2 = {54 52 69 63 6f 90 02 10 70 61 67 69 6e 61 30 31 90 00 } //01 00 
		$a_01_3 = {47 65 72 65 6e 63 69 61 64 6f 72 64 65 6a 61 6e 65 6c 61 73 } //00 00 
		$a_00_4 = {5d 04 00 } //00 68 
	condition:
		any of ($a_*)
 
}