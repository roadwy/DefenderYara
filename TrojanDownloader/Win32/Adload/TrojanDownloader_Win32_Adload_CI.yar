
rule TrojanDownloader_Win32_Adload_CI{
	meta:
		description = "TrojanDownloader:Win32/Adload.CI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {00 00 6a 00 70 00 64 00 65 00 73 00 6b 00 5f 00 00 00 } //1
		$a_00_1 = {00 00 2f 00 64 00 6c 00 63 00 61 00 6c 00 6c 00 00 00 } //1
		$a_03_2 = {ba 02 00 00 80 8b 45 e0 e8 ?? ?? ?? ?? b1 01 ba ?? ?? ?? ?? 8b 45 e0 e8 ?? ?? ?? ?? 84 c0 74 12 b9 02 00 00 00 ba ?? ?? ?? ?? 8b 45 e0 e8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}