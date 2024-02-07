
rule TrojanDownloader_O97M_Valak_YC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Valak.YC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 3a 2f 2f 25 32 30 25 32 30 40 6a 2e 6d 70 2f 61 73 64 61 61 73 64 61 61 73 64 6f 61 73 64 6f 64 6b 61 6f 73 } //01 00  p://%20%20@j.mp/asdaasdaasdoasdodkaos
		$a_00_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 70 75 64 6c 6f 61 6c 29 2e 45 78 65 63 20 66 75 64 61 } //00 00  CreateObject(pudloal).Exec fuda
	condition:
		any of ($a_*)
 
}