
rule Trojan_O97M_PShell_E{
	meta:
		description = "Trojan:O97M/PShell.E,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 3d 20 43 44 61 74 65 28 90 01 06 20 2b 20 53 69 6e 28 90 01 05 20 2b 20 90 01 05 29 20 2a 20 90 01 05 20 2a 20 43 49 6e 74 28 90 01 05 29 29 90 00 } //01 00 
		$a_01_1 = {20 3d 20 22 4f 77 65 72 53 48 65 6c } //00 00 
	condition:
		any of ($a_*)
 
}