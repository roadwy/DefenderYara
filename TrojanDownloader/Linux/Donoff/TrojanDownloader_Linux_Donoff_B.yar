
rule TrojanDownloader_Linux_Donoff_B{
	meta:
		description = "TrojanDownloader:Linux/Donoff.B,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Sub Document_Open()
		$a_01_1 = {52 65 73 69 64 65 6e 74 45 76 69 6c 46 6f 75 72 } //1 ResidentEvilFour
		$a_00_2 = {4c 69 6e 6b 54 77 6f 20 3d 20 22 3a 2f 2f 6a 6f 72 6e 61 6c 72 65 67 69 6f 6e 61 6c 2e 6e 65 74 } //1 LinkTwo = "://jornalregional.net
		$a_03_3 = {4c 69 6e 6b 54 68 72 65 65 20 3d 20 22 2f 69 6d 61 67 65 73 2f 41 6d 61 7a 6f 6e 2f [0-10] 2f 61 6c 69 6d 2e 65 78 65 } //1
		$a_01_4 = {20 54 65 6d 70 46 6f 75 72 74 68 20 3d 20 22 73 76 63 68 6f 73 74 } //1  TempFourth = "svchost
		$a_01_5 = {65 78 65 63 75 74 69 6f 6e 42 65 67 69 6e 20 3d 20 53 68 65 6c 6c 28 4d 61 6e 61 67 65 6d 65 6e 74 } //1 executionBegin = Shell(Management
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}