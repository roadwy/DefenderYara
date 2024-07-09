
rule Trojan_Win32_Ursnif_AU_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 14 81 c7 ?? ?? ?? ?? 0f b7 d1 8b 00 89 44 24 ?? 0f b6 c3 89 44 24 ?? 03 c2 03 f8 8d 3c 7a 03 3d } //1
		$a_02_1 = {8b 44 24 14 8b 7c 24 10 81 c7 ?? ?? ?? ?? 89 7c 24 ?? 89 38 8b c6 05 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 83 d5 ?? 83 f8 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}