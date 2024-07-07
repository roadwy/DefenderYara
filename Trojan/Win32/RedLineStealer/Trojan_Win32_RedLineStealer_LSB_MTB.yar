
rule Trojan_Win32_RedLineStealer_LSB_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.LSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {d3 ea 89 54 24 18 8b 44 24 50 01 44 24 18 8b 44 24 10 33 44 24 1c 89 74 24 34 89 44 24 10 89 44 24 58 8b 44 24 58 89 44 24 34 8b 44 24 18 31 44 24 34 8b 44 24 34 } //20
	condition:
		((#a_01_0  & 1)*20) >=20
 
}