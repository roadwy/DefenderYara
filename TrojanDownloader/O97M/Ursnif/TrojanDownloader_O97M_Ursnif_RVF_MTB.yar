
rule TrojanDownloader_O97M_Ursnif_RVF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.RVF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {2e 45 78 65 63 20 28 22 63 6d 64 20 2f 63 20 63 75 72 6c 20 68 74 74 70 3a 2f 2f 31 30 39 2e 32 34 38 2e 31 31 2e 31 35 35 2f 6e 65 74 77 6f 72 6b 2e 65 78 65 20 2d 6f 20 25 41 50 50 44 41 54 41 25 5c [0-14] 2e 65 78 65 } //1
		$a_03_1 = {2e 45 78 65 63 20 28 22 63 6d 64 20 2f 63 20 63 75 72 6c 20 68 74 74 70 3a 2f 2f 31 39 31 2e 31 30 31 2e 32 2e 33 39 2f 69 6e 73 74 61 6c 6c 61 7a 69 6f 6e 65 2e 65 78 65 20 2d 6f 20 25 41 50 50 44 41 54 41 25 5c [0-14] 2e 65 78 65 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}