
rule Trojan_Win32_LummaStealer_KKB_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.KKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 8b 4c 24 ?? 0f b6 0c 01 35 ?? ?? ?? ?? 89 44 24 04 8b 44 24 04 f7 d0 89 ca 21 c2 89 54 24 10 ?? ?? ?? ?? ?? ?? 21 c8 89 44 24 0c 8b 44 24 10 8b 4c 24 0c 09 c8 89 44 24 08 8b 44 24 08 04 ?? 8b 4c 24 ?? 8b 14 24 88 04 11 8b 04 24 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}
rule Trojan_Win32_LummaStealer_KKB_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.KKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {24 18 0f b6 04 08 89 ca 01 d2 81 e2 4e 6f ce 9a f7 da 8d 8c 11 a7 37 67 4d 89 4c 24 04 8b 4c 24 04 21 c1 f7 d1 89 4c 24 0c 8b 4c 24 04 89 ca f7 d2 89 c6 21 d6 31 c1 01 c1 29 f1 8b 44 24 0c 89 ca f7 d2 09 d0 8d 44 01 01 89 44 24 08 8b 44 24 08 04 5c 8b 4c 24 18 8b 14 24 88 04 11 8b 04 24 83 c0 01 89 04 24 } //20
	condition:
		((#a_01_0  & 1)*20) >=20
 
}