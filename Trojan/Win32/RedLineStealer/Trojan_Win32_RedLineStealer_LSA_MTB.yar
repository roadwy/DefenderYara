
rule Trojan_Win32_RedLineStealer_LSA_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.LSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 33 ca 89 4c 24 ?? 89 7c 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 54 24 ?? 89 54 24 ?? 89 3d ?? ?? ?? ?? 8b 44 24 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}