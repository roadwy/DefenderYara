
rule TrojanDownloader_O97M_IcedID_RVC_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.RVC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_02_0 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-05] 2e 70 64 66 } //1
		$a_02_1 = {4f 70 65 6e 20 22 47 45 54 22 2c 20 [0-05] 2c 20 46 61 6c 73 65 } //1
		$a_00_2 = {58 4f 64 46 6f 28 2e 53 68 61 70 65 73 28 31 29 2e 54 69 74 6c 65 29 } //1 XOdFo(.Shapes(1).Title)
		$a_02_3 = {4c 65 6e 28 [0-05] 29 20 54 6f 20 31 20 53 74 65 70 20 2d 31 } //1
		$a_00_4 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 61 64 6f 64 62 2e 73 74 72 65 61 6d 22 29 } //1 CreateObject("adodb.stream")
		$a_00_5 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 41 6a 67 70 48 28 33 29 20 26 20 22 2e 22 20 26 20 41 6a 67 70 48 28 33 29 20 26 20 22 72 65 71 75 65 73 74 2e 35 2e 31 22 29 } //1 CreateObject(AjgpH(3) & "." & AjgpH(3) & "request.5.1")
		$a_02_6 = {69 64 41 6d 47 28 [0-05] 29 2e 65 78 65 63 } //1
		$a_02_7 = {4e 43 6c 45 44 28 [0-05] 29 20 26 20 22 20 22 20 26 20 73 42 6d 6e 50 20 26 20 22 2c 53 68 6f 77 44 69 61 22 20 2b 20 22 6c 6f 67 41 20 2d 72 22 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_02_6  & 1)*1+(#a_02_7  & 1)*1) >=8
 
}