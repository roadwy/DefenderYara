
rule TrojanDownloader_O97M_EncDoc_VISA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VISA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 74 67 28 29 } //1 Public Function tg()
		$a_01_1 = {2e 65 78 65 63 20 74 67 } //1 .exec tg
		$a_01_2 = {4f 70 74 69 6f 6e 20 45 78 70 6c 69 63 69 74 } //1 Option Explicit
		$a_01_3 = {50 75 62 6c 69 63 20 53 75 62 20 62 75 74 74 6f 6e 31 5f 43 6c 69 63 6b 28 29 } //1 Public Sub button1_Click()
		$a_01_4 = {3d 20 53 70 6c 69 74 28 66 72 6d 2e 74 67 2c 20 22 20 22 29 } //1 = Split(frm.tg, " ")
		$a_01_5 = {66 72 6d 2e 62 75 74 74 6f 6e 31 5f 43 6c 69 63 6b } //1 frm.button1_Click
		$a_01_6 = {76 65 72 73 65 28 29 2e 6a 6f 69 6e 28 } //1 verse().join(
		$a_01_7 = {6f 76 65 54 6f 28 2d 31 30 30 2c 20 2d } //1 oveTo(-100, -
		$a_01_8 = {7a 65 54 6f 28 31 2c 20 31 29 } //1 zeTo(1, 1)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}