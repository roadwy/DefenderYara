
rule Trojan_Win32_Fragtor_C_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c1 c1 e0 0d 33 c8 8b c1 c1 e0 11 33 c8 8b c1 c1 e0 05 33 c8 } //1
		$a_01_1 = {43 6f 72 61 6e 32 2e 70 64 62 } //1 Coran2.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}