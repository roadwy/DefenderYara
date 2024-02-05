
rule Trojan_O97M_Obfuse_GA_MSR{
	meta:
		description = "Trojan:O97M/Obfuse.GA!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_00_0 = {4d 69 63 72 6f 73 6f 66 74 5f 4a 68 65 6e 67 48 65 69 20 3d 20 53 69 6d 70 6c 69 66 69 65 64 5f 41 72 61 62 69 63 28 22 64 6e 61 6d 6d 6f 43 64 65 64 6f 63 6e 45 2d 20 6e 65 64 64 69 48 20 77 6f 64 6e 69 57 2d 20 70 6f 4e 2d 20 61 74 53 2d 20 6c 6c 65 68 73 72 65 77 6f 70 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}