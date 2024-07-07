
rule TrojanDownloader_O97M_Ursnif_FTIV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.FTIV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //1 Sub autoopen()
		$a_01_1 = {50 75 62 6c 69 63 20 53 75 62 20 62 75 74 74 6f 6e 31 5f 43 6c 69 63 6b 28 29 } //1 Public Sub button1_Click()
		$a_03_2 = {2e 65 78 65 63 20 74 67 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //1
		$a_01_3 = {66 72 6d 2e 62 75 74 74 6f 6e 31 5f 43 6c 69 63 6b } //1 frm.button1_Click
		$a_01_4 = {3d 20 53 70 6c 69 74 28 66 72 6d 2e 74 67 2c 20 22 20 22 29 } //1 = Split(frm.tg, " ")
		$a_01_5 = {3c 68 74 6d 6c 3e 3c 62 6f 64 79 3e 3c 64 69 76 22 20 2b 20 22 20 69 64 3d 27 63 6f 6e 74 65 6e 74 27 3e 66 54 } //1 <html><body><div" + " id='content'>fT
		$a_03_6 = {43 6c 6f 73 65 20 23 31 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}