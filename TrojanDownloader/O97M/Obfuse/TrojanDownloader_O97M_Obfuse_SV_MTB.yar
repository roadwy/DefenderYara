
rule TrojanDownloader_O97M_Obfuse_SV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {53 65 74 20 41 20 3d 20 66 73 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 63 3a 5c 53 63 65 6e 65 31 5c 4c 6f 67 53 63 65 6e 65 [0-02] 2e 63 6d 64 22 2c 20 54 72 75 65 29 } //1
		$a_01_1 = {41 2e 57 72 69 74 65 4c 69 6e 65 20 28 43 53 74 72 28 77 6d 69 53 65 72 69 61 32 2e 6c 62 6c 46 41 51 73 63 65 6e 65 31 2e 43 61 70 74 69 6f 6e 29 29 } //1 A.WriteLine (CStr(wmiSeria2.lblFAQscene1.Caption))
		$a_01_2 = {4c 6f 61 64 42 79 74 65 73 46 75 6e 63 20 22 63 3a 5c 53 63 65 6e 65 31 5c 4c 6f 67 53 63 65 6e 65 31 2e 63 6d 64 22 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c 20 31 2c 20 30 } //1 LoadBytesFunc "c:\Scene1\LogScene1.cmd", vbNullString, 1, 0
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}