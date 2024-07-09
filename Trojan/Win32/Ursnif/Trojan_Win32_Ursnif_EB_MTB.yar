
rule Trojan_Win32_Ursnif_EB_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 c0 0f b6 4d e7 c1 e9 04 0f b6 d0 83 e2 0f 33 ca c1 e8 04 33 04 8b 89 45 c0 eb c5 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Ursnif_EB_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 1c 00 00 89 35 ?? ?? ?? ?? 81 25 ?? ?? ?? ?? 70 02 00 00 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 81 35 ?? ?? ?? ?? e0 30 00 00 89 2d ?? ?? ?? ?? 81 35 ?? ?? ?? ?? 5b 18 00 00 89 25 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}