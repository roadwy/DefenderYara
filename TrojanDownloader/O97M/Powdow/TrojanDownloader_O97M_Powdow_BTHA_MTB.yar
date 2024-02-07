
rule TrojanDownloader_O97M_Powdow_BTHA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BTHA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 53 75 62 20 62 75 74 74 6f 6e 31 5f 43 6c 69 63 6b 28 29 } //01 00  Public Sub button1_Click()
		$a_01_1 = {3d 20 22 22 20 26 20 45 78 4d 65 6d 6f 72 79 43 6c 65 61 72 20 26 20 22 22 } //01 00  = "" & ExMemoryClear & ""
		$a_01_2 = {2e 65 78 65 63 20 70 28 67 65 74 77 63 29 } //01 00  .exec p(getwc)
		$a_01_3 = {3d 20 53 70 6c 69 74 28 70 28 66 72 6d 2e 67 65 74 77 63 29 2c 20 22 20 22 29 } //01 00  = Split(p(frm.getwc), " ")
		$a_01_4 = {3d 20 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 6c 69 6e 6b 4c 65 6e 4c 65 66 74 2e 68 74 61 22 } //01 00  = "explorer.exe c:\programdata\linkLenLeft.hta"
		$a_01_5 = {66 72 6d 2e 62 75 74 74 6f 6e 31 5f 43 6c 69 63 6b } //01 00  frm.button1_Click
		$a_01_6 = {3c 68 74 6d 6c 3e 3c 62 6f 64 79 3e 3c 64 69 76 20 69 64 3d 27 63 6f 6e 74 65 6e 74 27 3e 66 54 74 6c } //00 00  <html><body><div id='content'>fTtl
	condition:
		any of ($a_*)
 
}