
rule TrojanDownloader_O97M_MuddyWater_GVA_MTB{
	meta:
		description = "TrojanDownloader:O97M/MuddyWater.GVA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 76 65 5f 6d 65 5f 5f 28 29 } //1 love_me__()
		$a_01_1 = {65 78 65 63 75 74 6f 72 2e 52 75 6e 20 69 6e 73 74 72 75 63 74 69 6f 6e 2c 20 30 2c 20 46 61 6c 73 65 } //1 executor.Run instruction, 0, False
		$a_01_2 = {43 3a 5c 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 5c 43 65 72 74 69 66 69 63 61 74 69 6f 6e 4b 69 74 2e 69 6e 69 } //1 C:\\ProgramData\\CertificationKit.ini
		$a_01_3 = {4d 73 67 42 6f 78 20 22 48 69 2c 20 68 61 76 65 20 61 20 6e 69 63 65 20 74 69 6d 65 20 3a 29 22 20 26 20 66 69 6c 65 50 61 74 68 } //1 MsgBox "Hi, have a nice time :)" & filePath
		$a_01_4 = {57 72 69 74 65 48 65 78 54 6f 46 69 6c 65 } //1 WriteHexToFile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}