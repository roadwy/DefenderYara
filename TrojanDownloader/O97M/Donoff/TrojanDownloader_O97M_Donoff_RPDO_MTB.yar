
rule TrojanDownloader_O97M_Donoff_RPDO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RPDO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 90 02 0a 29 73 65 74 90 02 0f 3d 90 02 0f 2e 6f 70 65 6e 74 65 78 74 66 69 6c 65 28 90 02 0f 2b 22 5c 72 66 65 63 6e 2e 76 62 73 22 2c 38 2c 74 72 75 65 29 90 1b 01 2e 77 72 69 74 65 6c 69 6e 65 66 90 1b 01 2e 63 6c 6f 73 65 90 08 00 02 63 72 65 61 74 65 6f 62 6a 65 63 74 90 02 2f 2e 6f 70 65 6e 28 90 02 1f 2b 22 5c 72 66 65 63 6e 2e 76 62 73 22 29 90 08 00 01 3d 67 65 74 74 69 63 6b 63 6f 75 6e 74 2b 28 66 69 6e 69 73 68 2a 31 30 30 30 29 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}