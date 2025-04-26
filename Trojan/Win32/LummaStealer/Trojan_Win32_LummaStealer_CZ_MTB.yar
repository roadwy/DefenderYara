
rule Trojan_Win32_LummaStealer_CZ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c2 f7 d2 21 ca f7 d1 21 c8 29 d0 89 44 24 08 8b 44 24 08 05 35 2e 1f fe 89 c1 83 e1 01 d1 e1 83 f0 01 01 c8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}