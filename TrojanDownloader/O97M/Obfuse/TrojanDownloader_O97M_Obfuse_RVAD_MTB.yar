
rule TrojanDownloader_O97M_Obfuse_RVAD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVAD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6f 62 6a 57 73 68 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 objWshShell = CreateObject("WScript.Shell")
		$a_01_1 = {45 6e 76 69 72 6f 6e 24 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 22 20 26 20 79 66 74 46 74 66 55 49 46 49 59 54 44 54 52 64 69 35 64 6a 74 66 64 55 53 55 44 54 49 64 75 74 44 73 64 6a 64 } //1 Environ$("USERPROFILE") & "\" & yftFtfUIFIYTDTRdi5djtfdUSUDTIdutDsdjd
		$a_03_2 = {49 6e 53 74 72 28 90 02 64 2c 20 4d 69 64 28 90 02 64 2c 20 69 2c 20 31 29 29 90 00 } //1
		$a_01_3 = {52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 22 50 6c 65 61 73 65 20 77 61 69 74 22 } //1 Range("A1").Value = "Please wait"
		$a_03_4 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 90 02 64 28 22 90 02 64 22 29 2c 20 46 61 6c 73 65 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}