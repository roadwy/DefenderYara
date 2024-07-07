
rule TrojanDownloader_O97M_Obfuse_PLM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PLM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 65 62 75 67 2e 50 72 69 6e 74 20 4d 73 67 42 6f 78 28 22 45 52 52 4f 52 21 22 2c 20 76 62 4f 4b 43 61 6e 63 65 6c 29 3b 20 72 65 74 75 72 6e 73 3b 20 31 } //1 Debug.Print MsgBox("ERROR!", vbOKCancel); returns; 1
		$a_01_1 = {3d 20 22 6d 73 68 74 61 } //1 = "mshta
		$a_01_2 = {3d 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 22 } //1 = "https://www.bitly.com/"
		$a_03_3 = {3d 20 22 6b 64 64 6a 90 02 0f 77 69 22 90 00 } //1
		$a_03_4 = {44 65 62 75 67 2e 50 72 69 6e 74 20 58 90 0c 02 00 44 65 62 75 67 2e 50 72 69 6e 74 20 59 90 0c 02 00 44 65 62 75 67 2e 50 72 69 6e 74 20 5a 90 00 } //1
		$a_03_5 = {44 65 62 75 67 2e 50 72 69 6e 74 20 28 53 68 65 6c 6c 28 58 20 2b 20 59 20 2b 20 5a 29 29 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}