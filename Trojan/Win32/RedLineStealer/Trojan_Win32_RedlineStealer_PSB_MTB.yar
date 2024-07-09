
rule Trojan_Win32_RedlineStealer_PSB_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.PSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f8 c1 ef 05 03 7d e4 c1 e0 04 03 45 e0 89 4d f4 33 f8 33 f9 89 7d 0c 8b 45 0c 01 05 ?? ?? ?? ?? 8b 45 0c 29 45 08 8b 45 08 c1 e0 04 03 45 dc 89 45 f0 8b 45 08 03 45 ec 89 45 f4 8b 45 08 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}