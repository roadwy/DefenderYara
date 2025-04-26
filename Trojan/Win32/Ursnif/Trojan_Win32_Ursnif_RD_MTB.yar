
rule Trojan_Win32_Ursnif_RD_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c6 99 8b f0 33 c0 3b d0 8b ?? ?? ?? 89 ?? ?? ?? 89 } //1
		$a_02_1 = {8a c2 6b d2 ?? 02 c3 04 ?? 0f b6 d8 03 da 8a 4c 24 ?? 83 c5 ?? 02 cb 83 6c 24 ?? ?? 89 6c 24 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}