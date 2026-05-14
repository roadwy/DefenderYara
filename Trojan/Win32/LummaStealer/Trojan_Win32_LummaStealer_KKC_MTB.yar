
rule Trojan_Win32_LummaStealer_KKC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.KKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 ce 83 e6 f5 89 cf 83 e7 0a 83 c9 0a 0f af cf 83 f7 0a 0f af fe 0f be d2 01 ca 8d 0c 17 83 c1 d0 0f b6 50 01 40 89 d6 83 c6 d0 83 fe 0a } //20
	condition:
		((#a_01_0  & 1)*20) >=20
 
}
rule Trojan_Win32_LummaStealer_KKC_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.KKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c2 81 f2 ?? ?? ?? ?? 89 14 24 8b 14 24 8b 34 24 21 ce 01 ca 29 f2 89 54 24 0c 8b 54 24 0c 8b 34 24 21 ce 29 f2 89 54 24 08 8b 4c 24 08 80 c1 ?? ?? ?? ?? ?? 40 83 f8 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}