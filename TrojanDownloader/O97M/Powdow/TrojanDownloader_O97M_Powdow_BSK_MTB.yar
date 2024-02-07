
rule TrojanDownloader_O97M_Powdow_BSK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BSK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 65 78 74 20 3d 20 50 72 65 66 69 78 31 28 29 20 2b 20 50 72 65 66 69 78 33 28 29 20 2b 20 50 72 65 66 69 78 32 28 29 } //01 00  text = Prefix1() + Prefix3() + Prefix2()
		$a_03_1 = {62 61 74 20 3d 20 22 90 02 1e 2e 62 61 74 22 90 00 } //01 00 
		$a_01_2 = {73 20 3d 20 73 20 2b 20 22 76 5c 6c 6c 65 68 53 72 65 77 6f 50 73 77 6f 64 6e 69 57 5c 32 33 6d 65 74 73 79 53 5c 73 77 6f 64 6e 69 57 5c 3a 43 22 } //01 00  s = s + "v\llehSrewoPswodniW\23metsyS\swodniW\:C"
		$a_01_3 = {74 65 78 74 20 3d 20 74 65 78 74 20 2b } //01 00  text = text +
		$a_01_4 = {73 20 3d 20 22 20 63 6e 65 2d 20 31 20 6e 69 77 2d 20 65 78 65 2e 6c 6c 65 68 73 72 65 77 6f 70 5c 30 2e 31 22 } //00 00  s = " cne- 1 niw- exe.llehsrewop\0.1"
	condition:
		any of ($a_*)
 
}