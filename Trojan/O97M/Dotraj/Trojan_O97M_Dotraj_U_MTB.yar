
rule Trojan_O97M_Dotraj_U_MTB{
	meta:
		description = "Trojan:O97M/Dotraj.U!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {44 69 6d 20 [0-10] 20 41 73 20 49 6e 74 65 67 65 72 90 0e 02 00 90 1b 00 20 3d 20 90 1d 02 00 90 0e 02 00 44 6f 20 57 68 69 6c 65 20 90 1b 00 20 3c 20 90 1d 02 00 20 2b 20 90 1d 02 00 90 0e 02 00 90 1b 00 20 3d 20 90 1b 00 20 2b 20 90 1d 02 00 3a 20 44 6f 45 76 65 6e 74 73 90 0e 02 00 4c 6f 6f 70 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}