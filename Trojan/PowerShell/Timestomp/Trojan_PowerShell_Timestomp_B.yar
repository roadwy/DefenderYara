
rule Trojan_PowerShell_Timestomp_B{
	meta:
		description = "Trojan:PowerShell/Timestomp.B,SIGNATURE_TYPE_CMDHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 [0-06] 28 00 67 00 65 00 74 00 2d 00 63 00 68 00 69 00 6c 00 64 00 69 00 74 00 65 00 6d 00 } //10
		$a_02_1 = {29 00 2e 00 63 00 72 00 65 00 61 00 74 00 69 00 6f 00 6e 00 74 00 69 00 6d 00 65 00 [0-06] 3d 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}