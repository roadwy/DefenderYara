
rule TrojanDownloader_Win32_Banload_AQK{
	meta:
		description = "TrojanDownloader:Win32/Banload.AQK,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_00_0 = {55 52 4c 4d 4f 4e 2e 44 4c 4c 00 00 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1
		$a_03_1 = {44 00 6a 00 e8 ?? ?? ?? ff 68 ?? ?? 44 00 e8 ?? ?? ?? ff 8b d8 85 db (74 24|0f 84) [0-04] 68 ?? ?? 44 00 } //10
		$a_03_2 = {44 00 6a 00 e8 ?? ?? ?? ff 6a 05 68 ?? ?? 44 00 e8 ?? ?? ?? ff 6a 00 6a 00 68 ?? ?? 44 00 68 ?? ?? 44 00 6a 00 e8 ?? ?? ?? ff 6a 05 68 ?? ?? 44 00 e8 ?? ?? ?? ff } //10
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10) >=21
 
}