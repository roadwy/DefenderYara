
rule TrojanDownloader_O97M_Emotet_AMDF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AMDF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {22 68 22 26 22 74 74 70 90 02 ff 2e 90 02 0f 22 2c 22 90 02 0a 22 68 74 22 26 22 74 70 90 02 ff 2e 90 1b 01 22 2c 22 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Emotet_AMDF_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AMDF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {22 68 22 26 22 74 74 70 90 02 ff 2e 90 02 0f 22 2c 22 90 02 0a 22 68 22 26 22 74 74 22 26 22 70 90 02 ff 2e 90 1b 01 22 2c 22 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Emotet_AMDF_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AMDF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 65 67 73 76 72 33 32 2e 65 78 65 90 02 5f 22 37 37 37 37 22 2c 22 90 02 0a 52 45 54 55 52 4e 90 02 0a 5c 65 66 68 6a 2e 64 6c 6c 90 02 0a 5c 65 66 68 6a 2e 64 6c 6c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Emotet_AMDF_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AMDF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 65 67 73 76 72 33 32 2e 65 78 65 90 02 5f 22 37 37 37 37 22 2c 22 90 02 0a 52 45 54 55 52 4e 90 00 } //1
		$a_03_1 = {5c 75 72 74 6a 2e 64 6c 6c 90 02 0a 5c 75 72 74 6a 2e 64 6c 6c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Emotet_AMDF_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AMDF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 22 26 22 65 67 22 26 22 73 76 22 26 22 72 33 22 26 22 32 2e 65 22 26 22 78 22 26 22 65 90 02 0a 5c 57 22 26 22 69 6e 22 26 22 64 6f 22 26 22 77 22 26 22 73 5c 90 02 0a 53 79 22 26 22 73 22 26 22 57 6f 22 26 22 77 22 26 22 36 34 5c 90 02 5f 2f 22 2c 22 90 02 5f 2f 22 2c 22 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Emotet_AMDF_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AMDF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 65 67 73 76 72 33 32 2e 65 78 65 90 02 0a 53 79 73 57 6f 77 36 34 5c 90 02 0a 5c 57 69 6e 64 6f 77 73 5c 90 02 0a 2c 30 2c 90 02 0a 2c 30 2c 30 29 90 02 2f 22 68 22 26 22 74 74 22 26 22 70 90 02 9f 22 2c 22 90 02 0a 22 68 22 26 22 74 74 22 26 22 70 90 02 9f 22 2c 22 90 02 0a 22 68 22 26 22 74 74 22 26 22 70 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Emotet_AMDF_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AMDF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 22 26 22 65 67 22 26 22 73 76 22 26 22 72 33 22 26 22 32 2e 65 22 26 22 78 22 26 22 65 90 02 0a 5c 57 22 26 22 69 6e 22 26 22 64 6f 22 26 22 77 22 26 22 73 5c 90 02 0a 53 79 22 26 22 73 22 26 22 57 6f 22 26 22 77 22 26 22 36 34 5c 29 90 02 0a 77 22 26 22 77 77 2e 90 02 5f 2f 22 2c 22 90 02 0a 77 22 26 22 77 77 2e 90 02 5f 2f 22 2c 22 90 02 0a 77 22 26 22 77 77 2e 90 02 5f 2f 22 2c 22 90 02 0a 77 22 26 22 77 77 2e 90 02 5f 2f 22 2c 22 90 02 0a 77 22 26 22 77 77 2e 90 02 5f 22 2c 22 2f 90 02 0a 77 22 26 22 77 77 2e 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}