
rule TrojanDownloader_Win32_Banload_PB{
	meta:
		description = "TrojanDownloader:Win32/Banload.PB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {43 3a 5c 43 6f 6d 6d 6f 6e 66 69 6c 65 73 5c 78 68 6f 73 74 90 01 01 2e 63 70 6c 90 00 } //01 00 
		$a_01_1 = {4d 31 2d 28 25 32 30 25 32 30 29 } //01 00 
		$a_01_2 = {63 6f 6e 74 61 64 6f 72 2e 70 68 70 3f 75 72 6c 3d 25 32 30 2d 7c 2d 25 32 30 } //00 00 
	condition:
		any of ($a_*)
 
}