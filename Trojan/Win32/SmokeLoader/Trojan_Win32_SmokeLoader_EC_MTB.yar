
rule Trojan_Win32_SmokeLoader_EC_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 04 89 01 c3 81 00 e1 34 ef c6 c3 } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}