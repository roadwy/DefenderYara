
rule TrojanDownloader_O97M_Obfuse_RF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {55 73 65 72 50 61 74 68 20 26 20 22 5c 73 61 6c 61 69 72 65 73 2e 76 62 73 22 } //1 UserPath & "\salaires.vbs"
		$a_00_1 = {47 65 74 46 69 6c 65 28 75 72 6c 2c 20 74 61 72 67 65 74 50 61 74 68 29 } //1 GetFile(url, targetPath)
		$a_00_2 = {66 73 6f 2e 42 75 69 6c 64 50 61 74 68 28 74 61 72 67 65 74 50 61 74 68 2c 20 22 22 5c 74 6f 6d 63 61 74 33 2e 65 78 65 22 22 29 22 } //1 fso.BuildPath(targetPath, ""\tomcat3.exe"")"
		$a_00_3 = {68 74 74 70 52 65 71 75 65 73 74 2e 4f 70 65 6e 20 22 22 47 45 54 22 22 2c 20 75 72 6c } //1 httpRequest.Open ""GET"", url
		$a_00_4 = {6f 75 74 46 69 6c 65 2e 57 72 69 74 65 20 43 68 72 28 41 73 63 } //1 outFile.Write Chr(Asc
		$a_01_5 = {57 73 68 53 68 65 6c 6c 2e 52 75 6e 20 6f 75 74 50 61 74 68 22 } //1 WshShell.Run outPath"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}