
rule TrojanDownloader_O97M_IcedID_RVN_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.RVN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {22 63 3a 5c 70 72 6f 67 72 61 22 2c 20 4f 70 74 69 6f 6e 61 6c 20 90 02 19 20 3d 20 22 74 61 22 90 00 } //01 00 
		$a_03_1 = {53 68 65 6c 6c 90 02 28 28 22 65 78 70 6c 6f 72 65 72 20 22 29 90 00 } //01 00 
		$a_01_2 = {53 70 6c 69 74 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 2c 20 22 78 22 29 } //01 00  Split(ActiveDocument.Range.Text, "x")
		$a_03_3 = {26 20 22 6d 64 61 74 61 5c 90 02 20 2e 68 22 20 26 90 00 } //01 00 
		$a_03_4 = {50 72 69 6e 74 20 23 31 2c 20 90 02 20 0d 0a 43 6c 6f 73 65 20 23 31 0d 0a 45 6e 64 20 53 75 62 90 00 } //01 00 
		$a_01_5 = {6f 75 74 20 26 20 43 68 72 28 61 72 72 28 63 6e 74 29 20 58 6f 72 20 31 30 30 29 } //00 00  out & Chr(arr(cnt) Xor 100)
	condition:
		any of ($a_*)
 
}