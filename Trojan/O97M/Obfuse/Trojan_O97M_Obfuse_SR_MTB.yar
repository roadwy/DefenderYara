
rule Trojan_O97M_Obfuse_SR_MTB{
	meta:
		description = "Trojan:O97M/Obfuse.SR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 78 65 63 43 6d 64 28 63 6d 64 6c 69 6e 65 20 41 73 20 53 74 72 69 6e 67 29 } //01 00 
		$a_01_1 = {3d 20 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 28 } //01 00 
		$a_03_2 = {45 78 65 63 43 6d 64 20 22 43 3a 5c 90 02 10 5c 90 02 0a 2e 42 41 54 22 90 00 } //01 00 
		$a_03_3 = {45 78 65 63 43 6d 64 20 22 43 3a 5c 90 02 0a 5c 90 02 0a 5c 90 02 0a 2e 65 78 65 22 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}