
rule Trojan_Win32_ICLoader_CCJW_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.CCJW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {32 c8 88 0d ?? ?? 66 00 8a 0d ?? ?? 66 00 80 c9 10 c0 e9 03 0f b6 d1 89 54 24 00 56 db 44 24 } //2
		$a_03_1 = {32 d1 8b 0d ?? ?? 66 00 88 15 ?? ?? 66 00 8b 15 ?? ?? 66 00 83 e2 04 03 ca 0f b6 15 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}