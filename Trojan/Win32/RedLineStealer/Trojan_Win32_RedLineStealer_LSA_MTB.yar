
rule Trojan_Win32_RedLineStealer_LSA_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.LSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 4c 24 90 01 01 33 ca 89 4c 24 90 01 01 89 7c 24 90 01 01 8b 44 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 54 24 90 01 01 89 54 24 90 01 01 89 3d 90 01 04 8b 44 24 90 00 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}