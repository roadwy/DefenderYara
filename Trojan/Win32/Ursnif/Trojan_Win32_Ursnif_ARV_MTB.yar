
rule Trojan_Win32_Ursnif_ARV_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.ARV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 d0 8b f3 2b f2 83 c1 ?? 83 ee ?? ff 4c 24 ?? 89 4c 24 ?? 0f 85 90 0a 76 00 69 ff ?? ?? ?? ?? 81 c5 ?? ?? ?? ?? 89 29 8b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 81 fa ?? ?? ?? ?? 75 ?? 6b ff ?? 8d 7c 1f ?? eb ?? 8b 15 ?? ?? ?? ?? 8d 7c 1a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}