
rule Trojan_O97M_EncDoc_RPM_MTB{
	meta:
		description = "Trojan:O97M/EncDoc.RPM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 73 74 72 72 65 76 65 72 73 65 28 22 74 78 74 2e 63 6e 65 2f 38 38 2f 35 34 2e 31 30 31 2e 32 33 31 2e 38 33 2f 2f 3a 70 74 74 68 22 29 } //01 00 
		$a_01_1 = {52 65 70 6c 61 63 65 28 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_O97M_EncDoc_RPM_MTB_2{
	meta:
		description = "Trojan:O97M/EncDoc.RPM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 63 68 72 28 38 30 29 2b 72 61 6e 67 65 28 22 63 36 22 29 2e 6e 6f 74 65 74 65 78 74 6d 73 6a 7a 32 3d 22 22 2b 65 65 65 65 77 6d 73 6a 7a 33 3d 6d 73 6a 7a 31 26 6d 73 6a 7a 32 6b 6c 73 61 64 28 29 2e 65 78 65 63 6d 73 6a 7a 33 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 6b 6c 73 61 64 28 29 61 73 6f 62 6a 65 63 74 73 65 74 6b 6c 73 61 64 3d 67 65 74 6f 62 6a 65 63 74 28 72 61 6e 67 65 28 22 63 37 22 29 2e 6e 6f 74 65 74 65 78 74 29 65 6e 64 66 75 6e 63 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}