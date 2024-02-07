
rule TrojanDownloader_O97M_IcedID_VI_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.VI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 75 74 20 3d 20 22 22 } //01 00  out = ""
		$a_03_1 = {53 68 65 6c 6c 20 90 02 ff 28 22 63 6d 64 20 2f 63 20 22 29 90 00 } //01 00 
		$a_03_2 = {20 26 20 22 72 73 5c 5c 70 75 62 6c 69 63 5c 5c 90 02 20 2e 68 22 20 26 20 90 00 } //01 00 
		$a_03_3 = {53 70 6c 69 74 28 90 02 ff 2c 20 22 23 22 29 90 00 } //01 00 
		$a_01_4 = {6f 75 74 20 26 20 43 68 72 28 61 72 72 28 63 6e 74 29 20 58 6f 72 20 31 32 31 29 } //00 00  out & Chr(arr(cnt) Xor 121)
	condition:
		any of ($a_*)
 
}