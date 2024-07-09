
rule Trojan_Win32_Ursnif_DHB_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f af cf be e0 ff ff ff 69 f9 7d 71 00 00 89 7c 24 ?? 8b 4c 24 ?? 8b 54 24 ?? 81 c2 ?? ?? ?? ?? 89 54 24 ?? 89 11 8d 0c 75 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b7 d9 39 7c 24 ?? 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}