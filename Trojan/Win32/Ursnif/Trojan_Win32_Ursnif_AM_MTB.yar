
rule Trojan_Win32_Ursnif_AM_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c3 89 44 24 ?? 6b c0 ?? 0f b7 f1 3b f0 74 ?? 6b 44 24 20 ?? 8b d6 2b d0 89 54 24 } //1
		$a_02_1 = {69 c0 82 53 00 00 89 11 89 15 ?? ?? ?? ?? 0f b7 c8 66 a3 ?? ?? ?? ?? 8d 86 ?? ?? ?? ?? 89 4c 24 ?? 8b f5 8d 14 41 8b cf 03 d0 8b 44 24 ?? 2b ca 89 54 24 ?? 99 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}