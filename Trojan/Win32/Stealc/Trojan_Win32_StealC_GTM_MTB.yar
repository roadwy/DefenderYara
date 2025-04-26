
rule Trojan_Win32_StealC_GTM_MTB{
	meta:
		description = "Trojan:Win32/StealC.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 33 d2 8b c7 f7 f1 8b 45 ?? 83 c4 ?? 68 ?? ?? ?? ?? 8a 0c 02 8b 55 ?? 32 0c 1a 88 0b } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_StealC_GTM_MTB_2{
	meta:
		description = "Trojan:Win32/StealC.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 41 f7 e5 c1 ea ?? 6b c2 ?? 8d 14 1e 0f b6 44 10 ?? 32 44 1e ?? 88 44 1f ?? 43 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}