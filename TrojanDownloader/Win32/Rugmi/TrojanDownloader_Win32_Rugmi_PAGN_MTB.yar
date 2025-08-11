
rule TrojanDownloader_Win32_Rugmi_PAGN_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.PAGN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 69 76 65 6d 20 69 6e 6a 65 63 74 6f 72 } //2 fivem injector
		$a_01_1 = {6d 6f 64 65 20 63 6f 6e 3a 20 63 6f 6c 73 3d 33 30 20 6c 69 6e 65 73 3d 31 30 } //2 mode con: cols=30 lines=10
		$a_01_2 = {6c 6f 61 64 65 72 2e 70 64 62 } //1 loader.pdb
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 } //1 URLDownloadToFileW
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}