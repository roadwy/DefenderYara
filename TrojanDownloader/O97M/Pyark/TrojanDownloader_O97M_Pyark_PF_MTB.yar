
rule TrojanDownloader_O97M_Pyark_PF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Pyark.PF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {66 69 6c 65 73 2e 30 30 30 77 65 62 68 6f 73 74 2e 63 6f 6d } //1 files.000webhost.com
		$a_00_1 = {3d 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 } //1 = "C:\ProgramData
		$a_00_2 = {3d 20 6c 6f 63 61 6c 5f 66 69 6c 65 20 26 20 22 5c 4e 69 73 53 72 76 2e 62 61 74 } //1 = local_file & "\NisSrv.bat
		$a_00_3 = {3d 20 6c 6f 63 61 6c 5f 66 69 6c 65 20 26 20 22 5c 53 65 72 76 69 63 65 2e 6c 6e 6b } //1 = local_file & "\Service.lnk
		$a_00_4 = {3d 20 45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 } //1 = Environ("APPDATA")
		$a_00_5 = {55 73 75 61 72 69 6f 20 3d 20 22 78 33 35 34 33 73 64 } //1 Usuario = "x3543sd
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}