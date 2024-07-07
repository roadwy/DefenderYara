
rule TrojanDownloader_O97M_Dotraj_I{
	meta:
		description = "TrojanDownloader:O97M/Dotraj.I,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {73 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 90 02 10 69 66 20 61 70 70 6c 69 63 61 74 69 6f 6e 2e 72 65 63 65 6e 74 66 69 6c 65 73 2e 63 6f 75 6e 74 20 3e 20 90 05 02 03 33 2d 39 20 74 68 65 6e 90 02 10 73 68 65 6c 6c 20 28 90 02 10 68 74 74 70 73 90 00 } //10
		$a_00_1 = {63 64 75 64 6c 65 79 } //5 cdudley
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5) >=10
 
}