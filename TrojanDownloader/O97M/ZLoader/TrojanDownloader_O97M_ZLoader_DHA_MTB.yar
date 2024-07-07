
rule TrojanDownloader_O97M_ZLoader_DHA_MTB{
	meta:
		description = "TrojanDownloader:O97M/ZLoader.DHA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {3d 20 43 72 65 61 74 65 46 69 6c 65 28 22 63 3a 5c 70 69 70 65 64 69 72 5c 6f 62 73 72 65 63 6f 72 64 2e 63 6d 64 22 20 5f } //1 = CreateFile("c:\pipedir\obsrecord.cmd" _
		$a_81_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 22 29 20 3e 3e 20 25 4e 4b 46 44 47 49 44 49 46 4e 53 4e 46 25 22 } //1 = CreateObject(""Scripting.FileSystemObject"") >> %NKFDGIDIFNSNF%"
		$a_81_2 = {63 3a 5c 70 69 70 65 64 69 72 5c 4e 4b 46 44 47 49 44 49 46 4e 53 4e 46 2e 76 62 73 20 68 74 74 70 3a 2f 2f 32 30 35 2e 31 38 35 2e 31 32 32 2e 32 34 36 2f 66 69 6c 65 73 2f 31 2e 65 78 65 20 63 3a 5c 70 69 70 65 64 69 72 5c 4c 4f 44 46 4f 4a 4b 46 47 2e 65 78 65 } //1 c:\pipedir\NKFDGIDIFNSNF.vbs http://205.185.122.246/files/1.exe c:\pipedir\LODFOJKFG.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}