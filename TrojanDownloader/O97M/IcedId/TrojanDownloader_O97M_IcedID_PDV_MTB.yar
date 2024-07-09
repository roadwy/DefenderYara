
rule TrojanDownloader_O97M_IcedID_PDV_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.PDV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 20 [0-0f] 28 22 65 78 70 6c 6f 72 65 72 20 22 29 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 90 0c 02 00 45 6e 64 20 53 75 62 } //1
		$a_03_1 = {46 75 6e 63 74 69 6f 6e 20 [0-0f] 28 [0-0f] 29 90 0c 02 00 73 63 72 4c 65 6e 67 74 68 20 3d 20 [0-0f] 20 26 20 22 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 62 75 74 74 43 61 70 74 2e 68 74 61 22 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}