
rule TrojanDownloader_Win32_Banload_WC{
	meta:
		description = "TrojanDownloader:Win32/Banload.WC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {59 8b c6 33 c9 ba 40 00 00 00 e8 90 01 04 c6 06 33 88 5e 30 c6 46 0a 2a 8d 45 84 89 46 04 66 c7 46 08 3c 00 56 e8 90 01 04 55 8b c3 90 00 } //01 00 
		$a_01_1 = {35 38 62 62 78 2e 63 6f 6d } //01 00 
		$a_01_2 = {6c 6f 63 61 6c 69 70 3d 00 } //01 00 
		$a_01_3 = {73 6f 66 74 66 69 6c 65 3d 00 } //00 00 
	condition:
		any of ($a_*)
 
}