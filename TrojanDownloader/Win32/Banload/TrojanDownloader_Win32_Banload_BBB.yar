
rule TrojanDownloader_Win32_Banload_BBB{
	meta:
		description = "TrojanDownloader:Win32/Banload.BBB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_02_0 = {5c 6f 66 66 90 02 30 75 70 64 61 74 65 2e 65 90 02 30 68 74 74 70 3a 90 02 50 2e 72 61 72 90 00 } //01 00 
		$a_01_1 = {55 61 63 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 00 } //01 00 
		$a_01_2 = {45 6e 61 62 6c 65 4c 55 41 00 } //00 00 
		$a_00_3 = {5d 04 00 00 0d } //38 03 
	condition:
		any of ($a_*)
 
}