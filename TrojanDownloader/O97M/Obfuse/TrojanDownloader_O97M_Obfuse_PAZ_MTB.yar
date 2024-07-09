
rule TrojanDownloader_O97M_Obfuse_PAZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PAZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 6d 73 68 74 61 2e 65 78 65 20 68 74 74 70 73 3a 2f 2f 77 77 77 2e 6d 69 6e 70 69 63 2e 64 65 2f 6b 2f 62 [0-15] 2f [0-15] 2f 20 22 2c 20 30 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}