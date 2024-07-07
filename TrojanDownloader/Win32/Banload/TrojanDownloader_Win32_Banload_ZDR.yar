
rule TrojanDownloader_Win32_Banload_ZDR{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZDR,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_00_0 = {6f 62 6a 46 53 4f 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 64 69 72 65 74 6f 72 69 6f 2e 74 78 74 } //3 objFSO.CreateTextFile("diretorio.txt
		$a_00_1 = {2e 6a 70 67 40 68 74 74 70 3a 2f 2f } //3 .jpg@http://
		$a_01_2 = {6f 62 6a 54 65 78 74 46 69 6c 65 2e 57 72 69 74 65 4c 69 6e 65 28 73 74 72 53 74 61 72 74 75 70 } //3 objTextFile.WriteLine(strStartup
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*3+(#a_01_2  & 1)*3) >=9
 
}