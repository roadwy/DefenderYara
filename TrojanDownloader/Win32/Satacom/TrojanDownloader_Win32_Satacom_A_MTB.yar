
rule TrojanDownloader_Win32_Satacom_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/Satacom.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {8d 04 52 2b c8 8a 44 0d f0 8b 4d ec 32 04 3b 88 04 39 47 3b 7d 18 72 c4 } //10
		$a_80_1 = {6f 6c 6c 79 64 62 67 2e 65 78 65 } //ollydbg.exe  3
		$a_80_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //URLDownloadToFileA  3
		$a_80_3 = {7d 69 64 3d 32 38 } //}id=28  3
		$a_80_4 = {47 65 74 54 65 6d 70 50 61 74 68 41 } //GetTempPathA  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}