
rule TrojanDownloader_O97M_Qakbot_PDT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PDT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 4f 4f 4f 43 43 43 58 58 58 } //1 .OOOCCCXXX
		$a_01_1 = {34 34 36 39 34 2c 34 39 38 35 31 34 34 36 37 36 2e 64 61 74 } //1 44694,4985144676.dat
		$a_03_2 = {75 52 6c 4d 6f 6e 90 02 03 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}