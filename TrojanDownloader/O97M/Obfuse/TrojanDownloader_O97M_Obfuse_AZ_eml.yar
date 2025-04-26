
rule TrojanDownloader_O97M_Obfuse_AZ_eml{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.AZ!eml,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 20 53 68 65 6c 6c 45 78 65 63 75 74 65 28 30 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c 20 22 6e 65 74 22 2c 20 22 75 73 65 [0-0a] 26 20 55 52 4c 2c 20 22 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 22 2c 20 76 62 48 69 64 65 29 } //1
		$a_01_1 = {6c 53 75 63 63 65 73 73 20 3d 20 53 68 65 6c 6c 45 78 65 63 75 74 65 28 30 2c 20 22 4f 70 65 6e 22 2c 20 55 52 4c 29 } //1 lSuccess = ShellExecute(0, "Open", URL)
		$a_01_2 = {53 65 74 20 6f 62 6a 4e 65 74 77 6f 72 6b 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 4e 65 74 77 6f 72 6b 22 29 } //1 Set objNetwork = CreateObject("WScript.Network")
		$a_01_3 = {55 70 64 61 74 65 64 55 52 4c 20 3d 20 52 6f 6f 74 55 52 4c 20 26 20 42 61 73 65 36 34 45 6e 63 6f 64 65 28 46 69 6c 6c 55 52 4c 29 } //1 UpdatedURL = RootURL & Base64Encode(FillURL)
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}