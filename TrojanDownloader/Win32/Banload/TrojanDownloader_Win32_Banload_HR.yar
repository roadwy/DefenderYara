
rule TrojanDownloader_Win32_Banload_HR{
	meta:
		description = "TrojanDownloader:Win32/Banload.HR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 68 65 6c 6c 33 32 2e 64 6c 6c 00 00 00 53 68 65 6c 6c 45 78 65 63 75 74 65 41 00 55 52 4c 4d 4f 4e 2e 44 4c 4c 00 00 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00 } //1
		$a_03_1 = {84 c0 74 0c 33 d2 b8 ?? ?? 44 00 e8 3d ff ff ff ba ?? ?? 44 00 b8 ?? ?? 44 00 e8 ?? ?? ff ff 84 c0 74 0c 33 d2 b8 ?? ?? 44 00 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}