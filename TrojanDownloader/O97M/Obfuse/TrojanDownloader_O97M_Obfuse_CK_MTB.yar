
rule TrojanDownloader_O97M_Obfuse_CK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.CK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 20 68 74 74 70 3a 2f 2f 6d 61 72 69 6e 67 61 72 65 73 65 72 76 61 73 2e 63 6f 6d 2e 62 72 2f 6d 61 63 2e 68 74 61 22 } //01 00  = " http://maringareservas.com.br/mac.hta"
		$a_01_1 = {3d 20 22 4d 22 } //01 00  = "M"
		$a_01_2 = {3d 20 22 53 22 } //01 00  = "S"
		$a_01_3 = {3d 20 22 48 22 } //01 00  = "H"
		$a_01_4 = {3d 20 22 54 22 } //01 00  = "T"
		$a_01_5 = {3d 20 22 41 22 } //00 00  = "A"
	condition:
		any of ($a_*)
 
}