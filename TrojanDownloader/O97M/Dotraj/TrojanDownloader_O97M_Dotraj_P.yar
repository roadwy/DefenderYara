
rule TrojanDownloader_O97M_Dotraj_P{
	meta:
		description = "TrojanDownloader:O97M/Dotraj.P,SIGNATURE_TYPE_MACROHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 4d 4c 32 2e 53 65 72 76 65 72 58 4d 4c 48 54 54 50 } //1 CreateObject("MSXML2.ServerXMLHTTP
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c } //1 CreateObject("WScript.Shell
		$a_03_2 = {57 72 69 74 65 20 [0-10] 2e 52 65 73 70 6f 6e 73 65 42 6f 64 79 } //1
		$a_02_3 = {50 75 62 6c 69 63 20 53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 [0-ff] [0-ff] [0-ff] 2e 65 78 65 63 20 28 22 [0-10] 2e 65 78 65 22 29 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_02_3  & 1)*10) >=12
 
}
rule TrojanDownloader_O97M_Dotraj_P_2{
	meta:
		description = "TrojanDownloader:O97M/Dotraj.P,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 4e 65 77 4d 61 63 72 6f 73 22 } //1 Attribute VB_Name = "NewMacros"
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 45 78 65 63 20 } //1 CreateObject("WScript.Shell").Exec 
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 } //1 CreateObject("WScript.Shell").Run 
		$a_01_3 = {63 20 3d 20 43 68 72 28 62 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_01_4 = {20 2b 20 52 65 70 6c 61 63 65 28 63 28 78 29 2c 20 } //1  + Replace(c(x), 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}