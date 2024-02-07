
rule TrojanDownloader_O97M_Ursnif_AY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 62 36 34 22 29 } //01 00  .createElement("b64")
		$a_01_1 = {3d 20 22 62 69 6e 2e 62 61 73 65 36 34 22 } //01 00  = "bin.base64"
		$a_03_2 = {4f 70 65 6e 20 90 02 08 20 2b 20 90 02 08 20 2b 20 22 90 02 05 5c 90 02 08 2e 78 73 6c 22 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 90 00 } //01 00 
		$a_03_3 = {43 61 6c 6c 20 56 42 41 2e 49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c 40 28 53 74 72 52 65 76 65 72 73 65 28 90 02 08 29 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}