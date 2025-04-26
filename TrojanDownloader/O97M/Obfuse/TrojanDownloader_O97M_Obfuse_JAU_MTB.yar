
rule TrojanDownloader_O97M_Obfuse_JAU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JAU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4b 01 00 00 65 01 00 00 72 01 00 00 6e 01 00 00 53 01 00 00 68 01 00 00 6c 01 00 00 45 01 00 00 78 01 00 00 63 01 00 00 75 01 00 00 74 01 00 00 41 } //1
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 6e 6f 6d 7a 6f 6f 2e 6d 6c 2f 64 73 2f 31 36 31 31 32 30 2e 67 69 66 } //1 https://nomzoo.ml/ds/161120.gif
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Obfuse_JAU_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JAU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {52 65 70 6c 61 63 65 28 [0-08] 2c 20 22 20 22 2c 20 22 22 2c 20 31 2c 20 2d 31 29 } //1
		$a_03_1 = {43 72 65 61 74 65 28 [0-08] 2c 20 4e 75 6c 6c 2c 20 4e 75 6c 6c 2c 20 69 6e 74 50 72 6f 63 65 73 73 49 44 29 } //1
		$a_01_2 = {68 74 74 70 3a 2f 2f 70 72 69 6d 65 74 6f 75 72 2e 6e 65 74 2e 62 72 2f 76 2e 74 78 74 } //1 http://primetour.net.br/v.txt
		$a_01_3 = {73 74 61 72 74 2d 70 72 6f 63 65 73 73 28 24 65 6e 76 3a 41 50 50 44 41 54 41 2b 27 5c 5c 27 2b 27 66 69 6c 65 2e 76 62 73 27 29 } //1 start-process($env:APPDATA+'\\'+'file.vbs')
		$a_03_4 = {4d 69 64 28 22 [0-20] 22 2c 20 31 2c 20 31 31 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Obfuse_JAU_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JAU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 01 00 00 68 01 00 00 65 01 00 00 6c 01 00 00 45 01 00 00 78 01 00 00 63 01 00 00 75 01 00 00 74 01 00 00 41 03 } //1
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 67 6f 6f 67 6c 65 72 65 73 75 6c 74 2e 69 6e 2f 64 73 2f 31 35 31 31 32 30 2e 67 69 66 } //1 https://googleresult.in/ds/151120.gif
		$a_01_2 = {68 74 74 70 3a 2f 2f 63 6c 6f 75 64 2e 63 2d 74 65 73 2e 67 72 2f 64 73 2f 31 35 31 31 32 30 2e 67 69 66 } //1 http://cloud.c-tes.gr/ds/151120.gif
		$a_01_3 = {68 74 74 70 73 3a 2f 2f 6d 61 68 61 72 69 73 68 69 6a 65 65 76 61 6e 2e 63 6f 6d 2f 64 73 2f 31 35 31 31 32 30 2e 67 69 66 } //1 https://maharishijeevan.com/ds/151120.gif
		$a_01_4 = {68 74 74 70 73 3a 2f 2f 31 39 72 61 63 6b 73 2e 63 6f 6d 2e 62 72 2f 64 73 2f 31 35 31 31 32 30 2e 67 69 66 } //1 https://19racks.com.br/ds/151120.gif
		$a_01_5 = {68 74 74 70 3a 2f 2f 6e 65 77 2e 6f 64 69 6e 67 72 61 64 2e 63 6f 6d 2f 64 73 2f 31 35 31 31 32 30 2e 67 69 66 } //1 http://new.odingrad.com/ds/151120.gif
		$a_01_6 = {68 74 74 70 73 3a 2f 2f 63 61 6d 65 78 73 75 72 69 6e 61 6d 65 2e 73 72 2f 64 73 2f 31 35 31 31 32 30 2e 67 69 66 } //1 https://camexsuriname.sr/ds/151120.gif
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=2
 
}