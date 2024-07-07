
rule Trojan_Win32_Fareit_FU_MTB{
	meta:
		description = "Trojan:Win32/Fareit.FU!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 00 61 00 4d 00 53 00 54 00 55 00 64 00 69 00 4f 00 20 00 43 00 52 00 6f 00 75 00 41 00 } //1 SaMSTUdiO CRouA
		$a_01_1 = {5a 00 41 00 4e 00 4f 00 4e 00 } //1 ZANON
		$a_01_2 = {54 00 4f 00 55 00 52 00 63 00 65 00 66 00 69 00 52 00 65 00 2c 00 20 00 56 00 4e 00 41 00 2e 00 } //1 TOURcefiRe, VNA.
		$a_01_3 = {54 00 48 00 75 00 6e 00 64 00 65 00 72 00 62 00 69 00 72 00 44 00 } //1 THunderbirD
		$a_01_4 = {41 00 55 00 44 00 41 00 43 00 49 00 54 00 79 00 20 00 73 00 6f 00 61 00 58 00 } //1 AUDACITy soaX
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}