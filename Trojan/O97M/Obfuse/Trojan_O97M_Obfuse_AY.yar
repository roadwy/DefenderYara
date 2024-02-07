
rule Trojan_O97M_Obfuse_AY{
	meta:
		description = "Trojan:O97M/Obfuse.AY,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {46 75 6e 63 74 69 6f 6e 20 90 02 20 28 29 90 00 } //01 00 
		$a_01_1 = {43 61 6c 6c 20 53 68 65 6c 6c 28 } //01 00  Call Shell(
		$a_02_2 = {3d 20 22 63 6d 64 20 2f 56 3a 4f 4e 2f 43 22 22 73 65 74 90 02 05 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}