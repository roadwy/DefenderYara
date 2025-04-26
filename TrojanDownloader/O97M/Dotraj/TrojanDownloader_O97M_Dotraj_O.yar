
rule TrojanDownloader_O97M_Dotraj_O{
	meta:
		description = "TrojanDownloader:O97M/Dotraj.O,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {53 68 65 6c 6c 45 78 65 63 75 74 65 20 [0-30] 28 22 59 32 31 6b 4c 6d 56 34 5a 51 3d 3d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}