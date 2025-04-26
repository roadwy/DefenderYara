
rule Trojan_Win32_RedlineStealer_AMAA_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 cf 41 66 25 c0 01 f7 ef c1 e9 ab 66 81 f3 88 01 66 c1 d1 d3 66 42 81 ce 97 00 00 00 81 f3 41 02 00 00 66 f7 e2 66 42 66 0b f0 66 c1 c6 3d } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}