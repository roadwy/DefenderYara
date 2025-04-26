
rule Trojan_Win32_Ursnif_GXZ_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 8b 45 f8 8b 00 83 e1 01 c1 e1 03 d3 e0 01 05 ?? ?? ?? ?? ff 4d fc ?? ?? ff 75 f4 ff 15 ?? ?? ?? ?? ff 75 fc 83 45 f8 04 ff 75 f4 ff 15 ?? ?? ?? ?? 3d 02 01 00 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Ursnif_GXZ_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 4d fb 0f b6 45 fb 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 0f be 11 33 d0 a1 38 20 45 00 03 85 ?? ?? ?? ?? 88 10 e9 ?? ?? ?? ?? 83 3d f8 21 45 00 3e ?? ?? a1 ?? ?? ?? ?? c6 40 10 46 33 c0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}