
rule TrojanDownloader_O97M_Ursnif_RT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.RT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {69 6f 79 79 66 2e 63 6f 6d 2f 69 7a 35 2f 79 61 63 61 2e 70 68 70 3f [0-0a] 2e 63 61 62 22 90 0a 4f 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 22 68 74 74 70 3a 2f 2f } //1
		$a_03_1 = {72 75 6e 20 22 72 [0-0a] 65 [0-0a] 67 [0-0a] 73 [0-0a] 76 [0-0a] 72 [0-0a] 33 32 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}