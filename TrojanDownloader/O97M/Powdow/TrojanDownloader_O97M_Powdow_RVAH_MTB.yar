
rule TrojanDownloader_O97M_Powdow_RVAH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVAH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 6b 69 6e 67 2e 6c 6f 6c 2c 20 76 62 48 69 64 65 } //01 00  Shell king.lol, vbHide
		$a_01_1 = {6b 69 6e 64 20 2b 20 22 20 68 74 74 70 3a 2f 2f 77 77 77 2e 6a 2e 6d 70 2f 61 68 73 64 69 61 68 77 69 64 61 69 75 77 64 22 } //01 00  kind + " http://www.j.mp/ahsdiahwidaiuwd"
		$a_01_2 = {64 20 2b 20 68 20 2b 20 74 20 2b 20 6a 20 2b 20 52 } //00 00  d + h + t + j + R
	condition:
		any of ($a_*)
 
}