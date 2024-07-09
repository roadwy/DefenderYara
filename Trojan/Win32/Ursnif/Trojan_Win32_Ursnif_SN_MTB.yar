
rule Trojan_Win32_Ursnif_SN_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {43 00 0f b6 05 ?? ?? ?? ?? 2b d1 83 c0 e1 83 ea 44 03 05 ?? ?? ?? ?? 03 c3 89 15 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 4d fd fe ff 8b b4 3b c3 e0 ff ff 03 c2 a3 ?? ?? ?? ?? 81 fd f1 72 8e 35 75 0d 0f b6 c2 6b c0 48 02 c1 a2 } //1
		$a_03_1 = {81 c6 68 02 34 01 89 35 ?? ?? ?? ?? 89 b4 3b c3 e0 ff ff 83 c7 04 8b 35 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 6b d6 48 03 d1 89 15 ?? ?? ?? ?? 81 ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Ursnif_SN_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.SN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 0f b7 08 8b 45 f8 8b 40 1c 8d 04 88 8b 04 18 03 c3 ff d0 5f 5e 33 c0 5b 8b e5 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}