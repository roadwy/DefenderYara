
rule TrojanDownloader_O97M_Qakbot_ALA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.ALA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {34 34 36 38 36 2e 34 38 30 32 39 37 38 30 30 39 2e 64 61 74 } //1 44686.4802978009.dat
		$a_01_1 = {2e 4f 4f 4f 43 43 43 58 58 58 } //1 .OOOCCCXXX
		$a_01_2 = {44 69 72 65 63 74 6f 72 79 41 } //1 DirectoryA
		$a_03_3 = {75 52 6c 4d 6f 6e 90 02 2f 72 33 32 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}