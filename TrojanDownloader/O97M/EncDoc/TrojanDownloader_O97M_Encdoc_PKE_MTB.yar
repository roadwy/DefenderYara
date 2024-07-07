
rule TrojanDownloader_O97M_Encdoc_PKE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Encdoc.PKE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 22 68 74 74 70 3a 2f 2f 39 31 2e 39 32 2e 31 32 30 2e 31 32 36 2f 90 02 1f 2e 65 78 65 22 90 00 } //1
		$a_03_1 = {2e 65 78 65 2e 65 78 65 20 26 26 20 90 02 2f 2e 65 78 65 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Encdoc_PKE_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Encdoc.PKE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 63 22 20 2b 20 22 6d 22 20 2b 20 22 64 } //1 = "c" + "m" + "d
		$a_01_1 = {3d 20 22 6d 73 67 62 6f 78 2f 72 6d 22 20 2b 20 22 73 68 22 20 2b 20 22 74 61 } //1 = "msgbox/rm" + "sh" + "ta
		$a_01_2 = {3d 20 22 68 74 74 70 73 3a 2f 2f 62 69 74 62 75 63 6b 65 74 2e 6f 72 67 2f 21 61 70 69 2f 32 2e 30 2f } //1 = "https://bitbucket.org/!api/2.0/
		$a_01_3 = {3d 20 22 73 6e 69 70 70 65 74 73 2f 68 6f 67 79 61 2f } //1 = "snippets/hogya/
		$a_01_4 = {3d 20 75 35 20 2b 20 75 36 20 2b 20 75 37 20 2b 20 75 38 } //1 = u5 + u6 + u7 + u8
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Encdoc_PKE_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Encdoc.PKE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,17 00 17 00 0a 00 00 "
		
	strings :
		$a_01_0 = {3d 20 45 6e 76 69 72 6f 6e 24 28 22 41 70 70 44 61 74 61 22 29 20 26 20 22 22 20 26 } //2 = Environ$("AppData") & "" &
		$a_01_1 = {3d 20 57 73 68 53 68 65 6c 6c 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 52 65 63 65 6e 74 22 29 } //2 = WshShell.SpecialFolders("Recent")
		$a_01_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //2 = CreateObject("WScript.Shell")
		$a_01_3 = {28 22 66 79 66 2f 64 73 64 64 22 29 } //10 ("fyf/dsdd")
		$a_01_4 = {28 22 66 79 66 2f 64 6b 6c 6f 70 6a 62 67 6e 6b 68 6f 79 67 6f 68 30 77 6b 69 68 6b 79 67 68 79 67 67 68 7b 65 74 67 69 77 63 6c 77 7b 74 65 68 67 77 74 65 77 74 30 6e 70 64 2f 68 6f 6a 6d 73 76 69 2e 74 6b 2f 78 78 78 30 30 3b 74 71 75 75 69 22 29 } //10 ("fyf/dklopjbgnkhoygoh0wkihkyghyggh{etgiwclw{tehgwtewt0npd/hojmsvi.tk/xxx00;tquui")
		$a_01_5 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c } //2 .Open "get",
		$a_01_6 = {3d 20 53 70 65 63 69 61 6c 50 61 74 68 20 2b } //2 = SpecialPath +
		$a_01_7 = {52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 22 72 65 73 69 7a 69 6e 67 2e 2e 2e 2e } //5 Range("A1").Value = "resizing....
		$a_01_8 = {4d 73 67 42 6f 78 20 22 72 65 73 69 7a 69 6e 67 2e 2e 2e 2e } //5 MsgBox "resizing....
		$a_01_9 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 65 6e 63 29 } //2 = StrReverse(enc)
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*5+(#a_01_8  & 1)*5+(#a_01_9  & 1)*2) >=23
 
}