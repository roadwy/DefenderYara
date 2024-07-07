
rule TrojanDownloader_O97M_MsiexecAbuse_B{
	meta:
		description = "TrojanDownloader:O97M/MsiexecAbuse.B,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_02_0 = {6d 73 69 65 78 65 63 90 02 30 68 74 74 70 90 00 } //6
	condition:
		((#a_02_0  & 1)*6) >=6
 
}