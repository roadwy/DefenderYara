
rule TrojanDownloader_O97M_Powdow_JJT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.JJT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 32 31 31 2e 32 35 32 2e 31 33 31 2e 32 32 34 2f 32 30 32 32 2f 6d 61 6c 2f 34 71 6d 61 6c 2e 67 69 66 } //1 http://211.252.131.224/2022/mal/4qmal.gif
		$a_01_1 = {3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 = VBA.CreateObject("WScript.Shell")
		$a_01_2 = {3d 20 22 2f 63 20 22 20 26 20 22 72 65 6e 61 6d 65 20 22 20 26 20 22 43 3a 5c 54 65 6d 70 5c 34 71 6d 61 6c 2e 67 69 66 20 34 71 6d 61 6c 5f 63 32 2e 65 78 65 } //1 = "/c " & "rename " & "C:\Temp\4qmal.gif 4qmal_c2.exe
		$a_01_3 = {53 68 65 6c 6c 20 28 22 43 3a 5c 54 65 6d 70 5c 34 71 6d 61 6c 5f 63 32 2e 22 20 26 20 22 65 22 20 26 20 22 78 65 22 29 } //1 Shell ("C:\Temp\4qmal_c2." & "e" & "xe")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}