
rule Trojan_Win32_Amatera_SDX_MTB{
	meta:
		description = "Trojan:Win32/Amatera.SDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {35 08 ab f2 e5 81 f2 d9 c1 b3 a7 89 45 f0 89 55 f4 8b 55 f0 81 c2 95 0a 22 27 8b 45 f4 } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}