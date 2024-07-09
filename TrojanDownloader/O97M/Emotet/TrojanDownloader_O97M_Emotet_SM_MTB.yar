
rule TrojanDownloader_O97M_Emotet_SM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {3a 2f 2f 39 31 2e 32 34 30 2e 31 31 38 2e 31 36 38 2f 7a 78 2f 63 76 2f 66 65 2e 68 74 6d 6c } //1 ://91.240.118.168/zx/cv/fe.html
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Emotet_SM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 43 72 65 61 74 65 } //1 .Create
		$a_01_1 = {2b 20 28 22 53 54 41 52 54 55 22 29 } //1 + ("STARTU")
		$a_01_2 = {3d 20 22 77 69 6e 6d 67 6d 74 73 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 } //1 = "winmgmts:Win32_Process"
		$a_03_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 90 05 0f 06 41 2d 5a 61 2d 7a 29 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Emotet_SM_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 7a 68 64 6b 6a 65 77 } //1 c:\programdata\zhdkjew
		$a_01_1 = {26 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 76 6b 77 65 72 2e 62 61 74 } //1 &c:\programdata\vkwer.bat
		$a_01_2 = {56 42 5f 4e 61 6d 65 20 3d 20 22 48 44 73 66 67 52 64 73 34 68 74 6b 64 65 } //1 VB_Name = "HDsfgRds4htkde
		$a_01_3 = {48 64 65 22 2c 20 22 22 } //1 Hde", ""
		$a_01_4 = {61 56 53 45 22 2c 20 22 22 } //1 aVSE", ""
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}