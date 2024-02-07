
rule Trojan_O97M_Dotraj_T_MTB{
	meta:
		description = "Trojan:O97M/Dotraj.T!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 73 70 61 67 22 20 26 20 22 2e 6a 22 20 26 20 90 02 24 20 26 20 22 73 65 22 90 00 } //01 00 
		$a_00_1 = {3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 } //00 00  = CallByName(
	condition:
		any of ($a_*)
 
}