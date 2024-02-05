
rule Trojan_O97M_Obfuse_BA{
	meta:
		description = "Trojan:O97M/Obfuse.BA,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 69 6d 20 77 44 54 69 49 4c 28 32 29 } //01 00 
		$a_01_1 = {77 44 54 69 49 4c 28 30 29 20 3d 20 49 6e 53 74 72 52 65 76 28 6a 6c 6a 4e 77 64 20 2b 20 69 6a 73 42 49 56 4d 6b 76 4a 71 64 55 44 6a 6a 77 5a 6a 4c 20 } //01 00 
		$a_01_2 = {44 69 6d 20 42 70 6a 4a 5a 63 28 33 29 } //01 00 
		$a_01_3 = {44 69 6d 20 54 6c 77 6c 46 66 28 33 29 } //00 00 
	condition:
		any of ($a_*)
 
}