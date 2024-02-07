
rule TrojanDownloader_O97M_Valak_YE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Valak.YE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 68 69 72 65 6d 65 29 2e 45 78 65 63 20 73 75 63 6b 6d 79 64 69 63 6b 66 6f 72 6e 6f 72 65 61 73 6f 6e } //01 00  CreateObject(hireme).Exec suckmydickfornoreason
		$a_01_1 = {70 3a 2f 2f 25 34 30 25 34 30 25 34 30 25 34 30 40 6a 2e 6d 70 2f } //01 00  p://%40%40%40%40@j.mp/
		$a_01_2 = {46 75 6e 63 74 69 6f 6e 20 68 69 72 65 6d 65 28 29 } //00 00  Function hireme()
	condition:
		any of ($a_*)
 
}