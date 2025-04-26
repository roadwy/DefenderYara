
rule TrojanDownloader_O97M_Powdow_BTHC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BTHC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 53 75 62 20 62 75 74 74 6f 6e 31 5f 43 6c 69 63 6b 28 29 } //1 Public Sub button1_Click()
		$a_01_1 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 72 6f 6f 74 5c 63 69 6d 76 32 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //1 = GetObject("winmgmts:root\cimv2:Win32_Process")
		$a_03_2 = {2e 43 72 65 61 74 65 20 70 28 72 6d 29 90 0c 02 00 45 6e 64 20 53 75 62 } //1
		$a_01_3 = {3d 20 53 70 6c 69 74 28 70 28 66 72 6d 2e 72 6d 29 2c 20 22 20 22 29 } //1 = Split(p(frm.rm), " ")
		$a_01_4 = {66 72 6d 2e 62 75 74 74 6f 6e 31 5f 43 6c 69 63 6b } //1 frm.button1_Click
		$a_03_5 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 22 61 74 68 2e [0-30] 5c 61 74 61 64 6d 61 72 67 6f 72 70 5c 3a 63 20 65 78 65 2e 72 65 72 6f 6c 70 78 65 5c 73 77 6f 64 6e 69 77 5c 3a 63 22 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}