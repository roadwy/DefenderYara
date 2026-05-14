
rule Trojan_Win32_Fragtor_VX_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.VX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c1 1a 01 00 00 2a c8 8a 1c 30 66 83 f1 1e 2c 3a b0 20 66 33 4c 24 be 66 ba 1c 00 66 03 d0 33 d1 80 f3 a1 88 1e 66 83 f1 1e } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}