
rule TrojanDownloader_O97M_Dotraj_H{
	meta:
		description = "TrojanDownloader:O97M/Dotraj.H,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {3d 20 53 68 65 6c 6c 28 90 1d 10 00 2c 20 90 0f 07 00 90 10 04 00 20 2d 20 90 0f 07 00 90 10 04 00 29 } //10
		$a_00_1 = {55 6e 6e 63 49 76 59 50 49 73 68 } //1 UnncIvYPIsh
		$a_00_2 = {69 6c 77 54 46 54 43 41 53 4e } //1 ilwTFTCASN
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=11
 
}