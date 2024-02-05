
rule Trojan_O97M_Obfuse_BQ{
	meta:
		description = "Trojan:O97M/Obfuse.BQ,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 22 51 65 54 78 58 65 46 2e } //01 00 
		$a_01_1 = {53 68 65 6c 6c 20 28 } //00 00 
	condition:
		any of ($a_*)
 
}