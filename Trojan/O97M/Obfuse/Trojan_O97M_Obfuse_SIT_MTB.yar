
rule Trojan_O97M_Obfuse_SIT_MTB{
	meta:
		description = "Trojan:O97M/Obfuse.SIT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {27 7a 69 70 50 61 74 68 20 3d 20 22 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 20 28 78 38 36 29 5c 57 69 6e 52 41 52 5c 77 69 6e 52 61 52 2e 65 78 65 22 20 26 20 22 20 78 20 2d 69 62 63 6b 20 22 20 26 20 46 6e 61 6d 65 20 26 20 22 20 2a 2e 2a 20 22 20 26 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 50 61 74 68 } //1 'zipPath = "C:\Program Files (x86)\WinRAR\winRaR.exe" & " x -ibck " & Fname & " *.* " & ThisDocument.Path
		$a_01_1 = {6f 53 74 72 65 61 6d 2e 53 61 76 65 54 6f 46 69 6c 65 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 50 61 74 68 20 26 20 22 5c 22 20 26 20 22 6d 61 6c 69 63 69 6f 75 73 2e 65 78 65 22 2c 20 32 } //1 oStream.SaveToFile ThisDocument.Path & "\" & "malicious.exe", 2
		$a_03_2 = {72 65 74 76 61 6c 20 3d 20 53 68 65 6c 6c 28 46 6e 61 6d 65 2c 20 76 62 4d 69 6e 69 6d 69 7a 65 64 46 6f 63 75 73 29 90 02 03 45 6e 64 20 53 75 62 90 00 } //1
		$a_01_3 = {6f 41 70 70 2e 4e 61 6d 65 53 70 61 63 65 28 66 46 6f 6c 64 65 72 29 2e 43 6f 70 79 48 65 72 65 20 6f 41 70 70 2e 4e 61 6d 65 53 70 61 63 65 28 66 4e 61 6d 65 29 2e 69 74 65 6d 73 } //1 oApp.NameSpace(fFolder).CopyHere oApp.NameSpace(fName).items
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}