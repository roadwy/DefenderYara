
rule Trojan_Win32_Ursnif_BM_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b d0 8b 35 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 2b d1 0f b7 cb 03 ce 81 f9 ?? ?? ?? ?? 75 90 08 30 00 0f b7 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 0f b7 cd 03 ca 89 0d ?? ?? ?? ?? 8b 0f } //1
		$a_02_1 = {0f b7 c5 89 0f 0f b7 fb 2b c7 89 0d ?? ?? ?? ?? 83 e8 ?? 99 8b c8 8b f2 8b c7 8b 7c 24 10 99 2b c1 1b d6 83 c0 ?? a3 ?? ?? ?? ?? 83 d2 00 83 c7 04 83 6c 24 14 ?? 89 15 ?? ?? ?? ?? 89 7c 24 10 74 0a a1 ?? ?? ?? ?? e9 ?? ?? ff ff } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}