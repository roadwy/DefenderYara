
rule Trojan_Win32_LummaStealer_KKE_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.KKE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 8b 4c 24 [0-0f] 35 ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 [0-14] 21 [0-05] 89 44 24 ?? 8b 44 24 [0-05] 8b 4c 24 [0-0f] c8 89 44 24 ?? 8b 44 24 08 [0-05] 8b 4c 24 18 8b 14 24 88 04 11 8b 04 24 [0-14] 89 04 24 eb } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}