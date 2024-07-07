
rule Trojan_Win32_Copak_FU_MTB{
	meta:
		description = "Trojan:Win32/Copak.FU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {31 03 81 c2 01 00 00 00 81 c1 90 01 04 43 39 f3 90 00 } //10
		$a_02_1 = {29 d2 8b 00 81 ea 90 01 04 81 e0 ff 00 00 00 47 81 ff 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}