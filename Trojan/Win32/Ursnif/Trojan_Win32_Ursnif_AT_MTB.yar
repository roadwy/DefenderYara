
rule Trojan_Win32_Ursnif_AT_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b f9 03 f7 8b 7c 24 ?? 8b ce 69 f6 ?? ?? ?? ?? 2b c8 03 ca 0f b7 d1 03 f2 8b ce 2b 0d ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 89 1f 83 e9 ?? 83 c7 ?? 83 6c 24 ?? ?? 0f b7 c9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}