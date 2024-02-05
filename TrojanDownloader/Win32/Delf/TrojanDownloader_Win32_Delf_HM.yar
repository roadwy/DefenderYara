
rule TrojanDownloader_Win32_Delf_HM{
	meta:
		description = "TrojanDownloader:Win32/Delf.HM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {59 00 00 00 47 45 54 20 2f 73 68 6f 77 2e 61 73 70 78 3f 66 69 6c 65 3d 39 39 39 39 26 68 61 73 68 3d 30 } //01 00 
		$a_00_1 = {5c 53 59 53 54 45 4d 33 32 5c 6d 73 76 66 77 36 34 2e 75 73 72 00 } //01 00 
		$a_01_2 = {64 89 20 68 c0 77 43 67 6a ff 6a 00 e8 07 db ff ff a3 58 bb 43 67 } //00 00 
	condition:
		any of ($a_*)
 
}