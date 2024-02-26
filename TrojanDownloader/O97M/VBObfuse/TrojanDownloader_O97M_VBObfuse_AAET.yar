
rule TrojanDownloader_O97M_VBObfuse_AAET{
	meta:
		description = "TrojanDownloader:O97M/VBObfuse.AAET,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {36 62 36 39 32 66 36 35 37 38 36 31 36 64 32 66 90 02 1f 32 65 36 35 37 38 36 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}