
rule TrojanDownloader_O97M_Powdow_RVCI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 2d 65 24 63 3b 22 2c 76 62 68 69 64 65 29 61 70 70 6c 69 63 61 74 69 6f 6e 2e 73 63 72 65 65 6e 75 70 64 61 74 69 6e 67 3d 74 72 75 65 65 6e 64 73 75 62 } //1 powershell-e$c;",vbhide)application.screenupdating=trueendsub
		$a_01_1 = {39 69 63 64 6f 64 68 72 77 6f 69 38 76 62 77 39 75 62 33 62 76 62 67 6c 68 7a 6e 6a 76 62 78 6c 76 64 73 35 79 64 73 39 6b 62 33 64 75 62 67 39 68 7a 63 38 79 6c 6d 76 34 7a 73 } //1 9icdodhrwoi8vbw9ub3bvbglhznjvbxlvds5yds9kb3dubg9hzc8ylmv4zs
		$a_01_2 = {61 75 74 6f 6f 70 65 6e 28 29 } //1 autoopen()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_RVCI_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 67 61 6e 68 76 63 75 63 75 73 6d 7a 71 64 6c 28 22 35 37 35 33 36 33 37 32 22 29 26 67 61 6e 68 76 63 75 63 75 73 6d 7a 71 64 6c 28 22 36 39 37 30 37 34 32 65 35 33 36 38 36 35 36 63 36 63 22 29 29 2e 72 75 6e 63 6d 64 6c 69 6e 65 } //1 createobject(ganhvcucusmzqdl("57536372")&ganhvcucusmzqdl("6970742e5368656c6c")).runcmdline
		$a_01_1 = {22 36 38 37 34 37 34 37 30 33 61 32 66 32 66 33 31 33 35 33 39 32 65 33 32 33 32 33 33 32 65 33 31 22 29 26 67 61 6e 68 76 63 75 63 75 73 6d 7a 71 64 6c 28 22 33 38 33 39 32 65 33 32 33 32 33 31 32 66 37 35 37 30 36 34 36 31 37 34 36 35 32 65 36 35 37 38 36 35 22 29 } //1 "687474703a2f2f3135392e3232332e31")&ganhvcucusmzqdl("38392e3232312f7570646174652e657865")
		$a_01_2 = {77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 } //1 workbook_open()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}