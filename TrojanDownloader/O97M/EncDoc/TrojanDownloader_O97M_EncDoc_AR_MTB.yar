
rule TrojanDownloader_O97M_EncDoc_AR_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {64 48 41 36 4c 79 38 78 4f 54 49 75 4d 6a 4d 32 4c 6a 45 33 4f 43 34 34 4d 43 38 33 65 69 38 77 4e 6a 45 33 4e 7a 63 7a 4c 6d 70 77 } //10 dHA6Ly8xOTIuMjM2LjE3OC44MC83ei8wNjE3NzczLmpw
		$a_00_1 = {63 31 78 51 64 57 4a 73 61 57 4e 63 64 32 68 77 5a 6e 64 72 63 6e 56 73 4c 6d 56 34 5a 53 4a 39 49 67 3d 3d } //10 c1xQdWJsaWNcd2hwZndrcnVsLmV4ZSJ9Ig==
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}
rule TrojanDownloader_O97M_EncDoc_AR_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,21 00 21 00 06 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f [0-28] 2f 90 12 0f 00 2f 44 } //10
		$a_03_1 = {68 74 74 70 3a 2f 2f [0-28] 2f 90 12 0f 00 2f 90 10 0f 00 2e 70 6e 67 } //10
		$a_03_2 = {09 00 00 43 3a 5c [0-0f] 5c } //10
		$a_01_3 = {7a 69 70 66 6c 64 72 } //1 zipfldr
		$a_01_4 = {4a 4a 43 43 43 4a } //1 JJCCCJ
		$a_01_5 = {64 54 6f 46 69 6c 65 41 } //1 dToFileA
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=33
 
}
rule TrojanDownloader_O97M_EncDoc_AR_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.AR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,16 00 16 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6a 6d 64 6d 65 6e 73 77 65 61 72 2e 63 6f 6d 2f 64 76 78 71 69 2f 44 } //10 http://jmdmenswear.com/dvxqi/D
		$a_01_1 = {68 74 74 70 3a 2f 2f 6a 6d 64 6d 65 6e 73 77 65 61 72 2e 63 6f 6d 2f 64 76 78 71 69 2f 35 33 30 33 34 30 2e 70 6e 67 } //10 http://jmdmenswear.com/dvxqi/530340.png
		$a_01_2 = {43 3a 5c 44 61 74 6f 70 5c } //1 C:\Datop\
		$a_01_3 = {7a 69 70 66 6c 64 72 } //1 zipfldr
		$a_01_4 = {4a 4a 43 43 43 4a } //1 JJCCCJ
		$a_01_5 = {64 54 6f 46 69 6c 65 41 } //1 dToFileA
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=22
 
}