
rule TrojanDownloader_O97M_Aptshot_A{
	meta:
		description = "TrojanDownloader:O97M/Aptshot.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 69 73 69 6e 67 5f 73 75 6e 20 3d 20 22 6b 65 72 6e 65 6c 33 32 22 } //1 rising_sun = "kernel32"
		$a_01_1 = {71 77 64 7a 78 63 76 20 3d 20 64 6e 6e 61 69 67 65 6a 28 67 77 65 61 73 64 66 2c 20 22 4c 6f 61 64 4c 69 62 72 61 72 79 41 22 29 } //1 qwdzxcv = dnnaigej(gweasdf, "LoadLibraryA")
		$a_01_2 = {77 65 74 71 64 61 77 65 20 3d 20 64 6e 6e 61 69 67 65 6a 28 67 77 65 61 73 64 66 2c 20 22 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 22 29 } //1 wetqdawe = dnnaigej(gweasdf, "GetProcAddress")
		$a_01_3 = {4c 4d 43 6f 6f 70 65 72 61 74 6f 72 20 3d 20 53 68 61 72 70 53 68 6f 6f 74 65 72 28 76 41 64 64 72 65 73 73 2c 20 30 2c 20 30 29 } //1 LMCooperator = SharpShooter(vAddress, 0, 0)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}