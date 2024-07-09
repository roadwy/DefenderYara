
rule Trojan_Win32_Ursnif_KVD_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.KVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {2b d1 0f af c2 33 85 ?? ff ff ff 8b 4d c0 8b 55 ?? 03 04 8a 8b 0d ?? ?? ?? ?? 03 8d ?? fe ff ff 88 01 90 09 06 00 8b 95 ?? ff ff ff } //2
		$a_02_1 = {8a 84 3e f5 d0 00 00 8b 0d ?? ?? ?? ?? 88 04 31 8b 4d fc 33 cd 5f e8 ?? ?? ?? ?? c9 c3 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}