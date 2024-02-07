
rule TrojanDownloader_O97M_EncDoc_SSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 2b 20 22 5c 4c 69 6e 6b 73 5c 90 17 05 06 09 06 06 08 64 65 73 69 67 6e 64 65 70 65 6e 64 61 6e 74 64 65 6e 69 61 6c 64 65 66 65 6e 64 64 65 63 69 73 69 76 65 2e 90 03 03 03 6c 6e 6b 64 61 74 22 90 00 } //02 00 
		$a_01_1 = {2e 64 65 6c 65 74 65 66 69 6c 65 20 28 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 2b 20 22 5c 4c 69 6e 6b 73 5c 2a 2e 6c 6e 6b 22 29 } //00 00  .deletefile (Environ("USERPROFILE") + "\Links\*.lnk")
	condition:
		any of ($a_*)
 
}