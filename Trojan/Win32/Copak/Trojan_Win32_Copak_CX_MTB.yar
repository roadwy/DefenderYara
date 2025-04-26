
rule Trojan_Win32_Copak_CX_MTB{
	meta:
		description = "Trojan:Win32/Copak.CX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 38 81 c3 [0-04] 81 c0 04 00 00 00 21 c9 81 c2 [0-04] 39 f0 75 e1 } //2
		$a_03_1 = {29 c1 81 e8 01 00 00 00 e8 [0-04] 31 1e 81 c0 [0-04] 46 39 fe 75 db } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}