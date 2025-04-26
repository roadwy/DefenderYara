
rule TrojanDownloader_O97M_ZLoader_HZA_MTB{
	meta:
		description = "TrojanDownloader:O97M/ZLoader.HZA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 45 78 70 6f 72 74 46 69 6c 65 20 3d 20 43 72 65 61 74 65 46 69 6c 65 28 22 63 3a 5c 70 69 70 65 64 69 72 5c 6f 62 73 72 65 63 6f 72 64 2e 63 6d 64 22 } //1 hExportFile = CreateFile("c:\pipedir\obsrecord.cmd"
		$a_01_1 = {22 65 63 68 6f 20 53 65 74 20 4e 65 48 44 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 22 4d 53 58 4d 4c 32 2e 53 65 22 20 2b 20 22 72 76 65 72 58 4d 4c 48 54 54 50 22 22 29 } //1 "echo Set NeHD = CreateObject(""MSXML2.Se" + "rverXMLHTTP"")
		$a_01_2 = {22 65 63 68 6f 20 53 65 74 20 61 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 22 29 } //1 "echo Set a = CreateObject(""Scripting.FileSystemObject"")
		$a_03_3 = {22 70 74 20 63 3a 5c 70 69 70 65 64 69 72 5c 4e 4b 46 44 47 49 44 49 46 4e 53 4e 46 2e 76 62 73 20 68 74 74 70 3a 2f 2f [0-a0] 2e 70 68 70 20 63 3a 5c 70 69 70 65 64 69 72 5c 4c 4f 44 46 4f 4a 4b 46 47 2e 65 78 65 22 } //1
		$a_03_4 = {22 70 74 20 63 3a 5c 70 69 70 65 64 69 72 5c 4e 4b 46 44 47 49 44 49 46 4e 53 4e 46 2e 76 62 73 20 68 74 74 70 3a 2f 2f [0-a0] 2e 65 78 65 20 63 3a 5c 70 69 70 65 64 69 72 5c 4c 4f 44 46 4f 4a 4b 46 47 2e 65 78 65 22 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}