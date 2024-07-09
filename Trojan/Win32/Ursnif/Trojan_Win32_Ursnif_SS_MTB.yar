
rule Trojan_Win32_Ursnif_SS_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 11 8b 4c 24 0c 89 54 24 10 8b 54 24 18 83 c2 3d 03 d1 89 15 ?? ?? ?? ?? 3d } //1
		$a_03_1 = {8d 4b 08 03 c8 66 89 0d ?? ?? ?? ?? 8b 4c 24 0c 3b 7c 24 18 8b 54 24 14 0f 42 3d ?? ?? ?? ?? 83 c1 3d 03 c1 8b 4c 24 10 81 c1 ?? ?? ?? ?? 0f b7 c0 89 0a 89 4c 24 10 89 0d ?? ?? ?? ?? 8d 50 45 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}