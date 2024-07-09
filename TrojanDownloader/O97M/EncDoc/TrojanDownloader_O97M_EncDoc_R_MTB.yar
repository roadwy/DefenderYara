
rule TrojanDownloader_O97M_EncDoc_R_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.R!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 74 22 20 2b 20 22 74 22 20 2b 20 22 70 22 20 2b 20 22 3a 22 20 2b 20 22 2f 22 20 2b 20 22 2f 22 20 2b } //1 = "t" + "t" + "p" + ":" + "/" + "/" +
		$a_01_1 = {3d 20 22 6d 22 20 2b 20 22 73 22 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 61 } //1 = "m" + "s" + "h" + "t" + "a
		$a_01_2 = {3d 20 22 2e 6a 2e 6d 70 2f } //1 = ".j.mp/
		$a_03_3 = {6a 2e 6d 70 2f 61 6a 64 64 64 73 64 73 64 6a 73 6a 63 6a 6f 73 64 6a 90 0a 3f 00 68 74 74 70 3a 2f 2f 77 77 77 2e } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*3) >=3
 
}
rule TrojanDownloader_O97M_EncDoc_R_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.R!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_01_0 = {72 6f 63 6b 73 74 61 72 2e 70 68 70 } //3 rockstar.php
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 73 70 64 74 65 78 74 69 6c 65 2e 63 6f 6d 2f 73 70 6f 72 74 2f } //3 https://spdtextile.com/sport/
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 73 70 64 74 65 78 74 69 6c 65 2e 63 6f 6d 2f 73 70 6f 72 74 2f 72 6f 63 6b 73 74 61 72 2e 70 68 70 } //3 https://spdtextile.com/sport/rockstar.php
		$a_03_3 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65 } //1
		$a_01_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_01_6 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 41 } //1 CreateDirectoryA
		$a_01_7 = {55 52 4c 4d 4f 4e } //1 URLMON
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=11
 
}
rule TrojanDownloader_O97M_EncDoc_R_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.R!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {46 75 6e 63 74 69 6f 6e 20 52 75 6e 41 6e 64 47 65 74 43 6d 64 28 29 0d 0a [0-0f] 3d 20 53 68 65 6c 6c 28 22 63 6d 64 2e 65 78 65 20 2f 63 20 22 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 49 45 58 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 70 47 59 30 66 77 37 33 27 29 22 22 22 29 } //1
		$a_03_1 = {34 35 2e 31 34 2e 32 32 36 2e 32 32 31 2f 63 64 66 65 2f 46 61 63 6b 2e 6a 70 67 27 29 22 90 0a 7f 00 20 2d 6e 6f 65 78 69 74 20 20 20 2d 63 6f 6d 6d 61 20 49 6e 76 6f 6b 65 2d 45 78 70 72 65 73 73 69 6f 6e 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 4e 6c 6f 41 64 53 54 52 69 4e 67 2e 49 6e 76 6f 6b 65 28 27 68 74 74 70 3a 2f 2f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}