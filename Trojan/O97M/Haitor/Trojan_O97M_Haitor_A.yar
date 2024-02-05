
rule Trojan_O97M_Haitor_A{
	meta:
		description = "Trojan:O97M/Haitor.A,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 68 65 6c 6c 20 53 74 72 43 6f 6e 76 28 44 65 63 6f 64 65 42 61 73 65 36 34 28 22 59 32 31 6b 4c 6d 56 34 5a 53 41 76 59 79 41 67 63 47 6c 75 5a 79 42 73 62 32 4e 68 62 47 68 76 63 33 51 67 4c 57 34 67 4d 54 41 77 49 43 59 6d 49 41 3d 3d 22 29 2c 20 76 62 55 6e 69 63 6f 64 65 29 20 26 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 } //00 00 
	condition:
		any of ($a_*)
 
}