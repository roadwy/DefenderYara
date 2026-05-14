
rule Trojan_Win32_LummaStealer_KKA_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.KKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 8b 4c 24 10 0f b6 0c 01 35 ?? ?? ?? ?? 89 44 24 04 8b 44 24 04 [0-03] 54 24 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}
rule Trojan_Win32_LummaStealer_KKA_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.KKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 08 89 ce 81 f6 ?? ?? ?? ?? 89 75 f0 8b 75 f0 21 d6 89 75 e4 8b 75 f0 21 d6 89 75 e8 8b 75 [0-14] 01 d6 [0-1e] ec 8b [0-1e] 83 f9 14 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}