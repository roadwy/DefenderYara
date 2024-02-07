
rule TrojanDownloader_Win32_VB_XX{
	meta:
		description = "TrojanDownloader:Win32/VB.XX,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {2e 00 39 00 37 00 38 00 63 00 66 00 2e 00 63 00 6f 00 6d 00 2f 00 6d 00 61 00 2f 00 90 01 02 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_02_1 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 48 00 65 00 6c 00 70 00 5c 00 90 01 02 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_00_2 = {79 00 75 00 79 00 61 00 6e 00 7a 00 68 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  yuyanzhe.exe
		$a_01_3 = {79 75 79 61 6e 7a 68 65 } //00 00  yuyanzhe
	condition:
		any of ($a_*)
 
}