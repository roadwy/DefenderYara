
rule TrojanDownloader_O97M_EncDoc_VI_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 75 6e 64 6c 6c 33 32 } //1 rundll32
		$a_01_1 = {68 74 74 70 3a 2f 2f 39 31 2e 39 32 2e 31 30 39 2e 31 36 2f 69 6d 61 67 65 73 2f 72 65 64 74 61 6e 6b 2e 70 6e 67 } //1 http://91.92.109.16/images/redtank.png
		$a_01_2 = {63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 74 65 73 74 2e 70 6e 67 } //1 c:\users\public\test.png
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_EncDoc_VI_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 20 22 22 2c 20 22 63 6d 64 2e 65 78 65 20 2f 73 20 2f 63 20 } //1 i "", "cmd.exe /s /c 
		$a_01_1 = {56 42 41 2e 53 68 65 6c 6c } //1 VBA.Shell
		$a_01_2 = {3d 20 52 65 70 6c 61 63 65 } //1 = Replace
		$a_01_3 = {63 3a 5c 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 5c 69 6e 64 65 78 2e 68 } //1 c:\\programdata\\index.h
		$a_01_4 = {50 75 62 6c 69 63 20 53 75 62 20 69 } //1 Public Sub i
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_EncDoc_VI_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {2e 68 22 20 26 20 [0-0f] 20 26 20 22 61 } //1
		$a_01_1 = {43 61 6c 6c 20 56 42 41 2e 53 68 65 6c 6c 28 68 74 6d 6c } //1 Call VBA.Shell(html
		$a_01_2 = {69 20 22 74 22 2c 20 22 63 6d 64 20 2f 73 20 2f 6b } //1 i "t", "cmd /s /k
		$a_03_3 = {52 65 70 6c 61 63 65 28 [0-ff] 2c 20 22 [0-0f] 22 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_EncDoc_VI_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 75 6e 63 43 6f 6d 70 61 72 65 44 65 66 69 6e 65 20 26 20 4d 69 64 28 76 61 72 49 2c 20 28 63 6f 72 65 42 72 20 2d 20 69 29 2c 20 31 29 } //1 funcCompareDefine & Mid(varI, (coreBr - i), 1)
		$a_01_1 = {50 72 69 6e 74 20 23 31 2c 20 63 6f 72 65 44 65 66 69 6e 65 54 6f 28 22 64 74 31 79 6f 22 29 } //1 Print #1, coreDefineTo("dt1yo")
		$a_01_2 = {46 6f 72 20 69 20 3d 20 30 20 54 6f 20 63 6f 72 65 42 72 20 2d 20 31 } //1 For i = 0 To coreBr - 1
		$a_01_3 = {4c 65 6e 28 76 61 72 49 29 } //1 Len(varI)
		$a_01_4 = {56 42 41 2e 53 68 65 6c 6c 28 63 6f 6d 70 61 72 65 50 72 6f 63 48 74 6d 6c 20 26 20 63 6f 72 65 46 6f 72 43 6f 72 65 29 } //1 VBA.Shell(compareProcHtml & coreForCore)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_EncDoc_VI_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {67 75 68 75 69 6f 6f 20 79 74 75 79 67 79 20 6d 62 76 6d 6e 62 6b 69 75 } //1 guhuioo ytuygy mbvmnbkiu
		$a_01_1 = {2e 52 75 6e 28 } //1 .Run(
		$a_01_2 = {76 78 63 6e 20 6e 6d 76 6d 20 6b 75 6b 20 65 74 20 2c 6e 62 6e 20 68 68 66 67 64 } //1 vxcn nmvm kuk et ,nbn hhfgd
		$a_03_3 = {6f 69 75 70 28 ?? ?? ?? 29 20 26 20 6f 69 75 70 28 31 39 39 29 20 26 20 6f 69 75 70 28 31 39 30 29 20 26 20 6f 69 75 70 28 31 35 34 29 20 26 20 6f 69 75 70 28 31 36 39 29 20 26 20 6f 69 75 70 28 ?? ?? ?? 29 20 26 } //1
		$a_01_4 = {43 68 72 28 66 64 73 67 20 2d 20 31 32 32 29 } //1 Chr(fdsg - 122)
		$a_01_5 = {3d 20 22 57 53 43 72 69 70 74 2e 73 68 65 6c 6c 22 } //1 = "WSCript.shell"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_EncDoc_VI_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 62 6a 2e 4f 70 65 6e 20 22 50 4f 22 20 26 20 22 53 54 22 2c 20 54 72 69 6d 28 72 65 71 75 65 73 55 72 6c 29 2c 20 46 61 6c 73 65 } //1 obj.Open "PO" & "ST", Trim(requesUrl), False
		$a_01_1 = {6f 62 6a 2e 73 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 20 22 43 6f 6e 74 65 6e 74 2d 54 79 70 65 22 2c 20 22 61 70 70 22 20 26 20 22 6c 69 63 22 20 26 20 22 61 74 69 22 20 26 20 22 6f 6e 2f 78 2d 77 22 20 26 20 22 77 77 2d 66 22 20 26 20 22 6f 72 6d 2d 75 72 6c 22 20 26 20 22 65 6e 63 22 20 26 20 22 6f 64 65 64 } //1 obj.setRequestHeader "Content-Type", "app" & "lic" & "ati" & "on/x-w" & "ww-f" & "orm-url" & "enc" & "oded
		$a_01_2 = {6f 62 6a 2e 73 65 6e 64 20 28 64 61 74 61 29 } //1 obj.send (data)
		$a_01_3 = {53 70 6c 69 74 28 6c 69 6e 65 73 28 69 29 2c 20 22 7c 22 2c 20 33 } //1 Split(lines(i), "|", 3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}