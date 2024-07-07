
rule TrojanDownloader_BAT_Banload_AR{
	meta:
		description = "TrojanDownloader:BAT/Banload.AR,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 65 6d 6f 76 65 00 66 63 6b 2e 65 78 65 } //10 敒潭敶昀正攮數
		$a_01_1 = {66 63 6b 2e 52 65 73 6f 75 72 63 65 73 } //10 fck.Resources
		$a_03_2 = {44 69 73 70 6f 73 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f 90 02 0a 68 74 74 70 90 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_03_2  & 1)*1) >=21
 
}
rule TrojanDownloader_BAT_Banload_AR_2{
	meta:
		description = "TrojanDownloader:BAT/Banload.AR,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 00 57 00 69 00 72 00 65 00 58 00 5c 00 61 00 63 00 69 00 6d 00 2e 00 65 00 78 00 65 00 } //10 \WireX\acim.exe
		$a_01_1 = {5c 00 57 00 69 00 72 00 65 00 58 00 5c 00 76 00 6f 00 78 00 2e 00 7a 00 69 00 70 00 } //10 \WireX\vox.zip
		$a_03_2 = {2e 7a 69 70 90 01 06 4d 79 2e 53 65 74 74 69 6e 67 73 90 00 } //1
		$a_03_3 = {44 69 73 70 6f 73 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f 90 02 0a 68 74 74 70 90 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=21
 
}
rule TrojanDownloader_BAT_Banload_AR_3{
	meta:
		description = "TrojanDownloader:BAT/Banload.AR,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {44 69 73 70 6f 73 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f 90 02 0a 68 74 74 70 90 00 } //1
		$a_03_1 = {2e 7a 69 70 90 02 08 4d 79 2e 53 65 74 74 69 6e 67 73 90 02 08 4d 79 2e 43 6f 6d 70 75 74 65 72 90 00 } //1
		$a_03_2 = {13 06 11 06 28 90 01 02 00 06 6f 90 01 02 00 06 6f 90 01 02 00 0a 13 05 72 90 01 02 00 70 28 90 01 02 00 0a 13 07 02 6f 90 01 02 00 06 11 07 72 90 01 02 00 70 28 90 01 02 00 0a 6f 90 01 02 00 0a 00 11 07 72 90 01 02 00 70 28 90 01 02 00 06 6f 90 00 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*10) >=12
 
}