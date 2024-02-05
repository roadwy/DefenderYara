
rule Trojan_O97M_Obfuse_CS{
	meta:
		description = "Trojan:O97M/Obfuse.CS,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 0d 0a } //01 00 
		$a_03_1 = {3d 20 53 68 65 6c 6c 28 90 01 02 90 02 20 20 2b 20 90 01 02 90 02 20 20 2b 20 90 02 60 2c 20 76 62 48 69 64 65 29 0d 0a 0d 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}