
rule Trojan_Win32_Ursnif_ARH_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.ARH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 ff 0f b6 05 ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 03 c2 89 44 24 ?? 3d 0f c6 00 00 74 } //1
		$a_02_1 = {8b cf 2b ca 83 e9 ?? ff 4c 24 ?? 0f 85 90 0a 25 00 0f b6 15 ?? ?? ?? ?? 83 44 24 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}