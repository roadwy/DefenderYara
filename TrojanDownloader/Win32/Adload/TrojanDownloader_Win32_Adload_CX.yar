
rule TrojanDownloader_Win32_Adload_CX{
	meta:
		description = "TrojanDownloader:Win32/Adload.CX,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_02_0 = {70 68 70 3f 6d 3d ?? 26 6d 61 63 3d 3a 6d 61 63 26 66 3d 3a 66 69 6c 65 } //2
		$a_00_1 = {24 24 33 33 36 36 39 39 2e 62 61 74 } //1 $$336699.bat
		$a_03_2 = {ba 44 00 00 00 e8 ?? ?? ?? ff c7 85 08 fe ff ff 01 00 00 00 66 c7 85 0c fe ff ff 00 00 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}