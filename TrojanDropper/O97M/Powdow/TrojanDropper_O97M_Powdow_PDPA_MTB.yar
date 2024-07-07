
rule TrojanDropper_O97M_Powdow_PDPA_MTB{
	meta:
		description = "TrojanDropper:O97M/Powdow.PDPA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 22 63 6d 64 2f 63 65 63 68 6f 22 26 73 62 79 74 65 73 26 22 3e 25 74 6d 70 25 5c 6f 75 70 2e 64 61 74 26 26 63 65 72 74 75 74 69 6c 2d 64 65 63 6f 64 65 25 74 6d 70 25 5c 6f 75 70 2e 64 61 74 25 6c 6f 63 61 6c 61 70 70 64 61 74 61 25 5c 6d 69 63 72 6f 73 6f 66 74 5c 6f 66 66 69 63 65 5c 6f 75 70 2e 76 62 73 22 6e } //1 ="cmd/cecho"&sbytes&">%tmp%\oup.dat&&certutil-decode%tmp%\oup.dat%localappdata%\microsoft\office\oup.vbs"n
		$a_01_1 = {63 6d 64 2f 63 70 69 6e 67 2d 6e 35 31 32 37 2e 30 2e 30 2e 31 26 26 25 6c 6f 63 61 6c 61 70 70 64 61 74 61 25 5c 6d 69 63 72 6f 73 6f 66 74 5c 6f 66 66 69 63 65 5c 6f 75 70 2e 76 62 73 22 6e 3d 73 68 65 6c 6c 28 73 63 6d 64 6c 69 6e 65 2c 76 62 68 69 64 65 29 65 6e 64 73 75 62 } //1 cmd/cping-n5127.0.0.1&&%localappdata%\microsoft\office\oup.vbs"n=shell(scmdline,vbhide)endsub
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}