
rule TrojanDownloader_O97M_EncDoc_PAA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 50 22 20 2b 20 [0-09] 28 [0-09] 29 2c 20 90 1b 00 28 [0-0f] 29 2c 20 22 22 2c 20 22 22 2c 20 30 } //1
		$a_03_1 = {3e 20 31 20 54 68 65 6e 0d 0a 20 20 20 73 74 72 33 20 3d 20 52 69 67 68 74 28 73 74 72 32 2c 20 31 29 20 26 20 74 65 6d 70 0d 0a 20 20 20 74 65 6d 70 20 3d 20 73 74 72 33 0d 0a 45 6e 64 20 49 66 0d 0a 4e 65 78 74 0d 0a [0-09] 20 3d 20 74 65 6d 70 20 ?? 20 61 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}