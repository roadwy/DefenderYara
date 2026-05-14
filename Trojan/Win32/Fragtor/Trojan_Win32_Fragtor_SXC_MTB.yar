
rule Trojan_Win32_Fragtor_SXC_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.SXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 e7 c1 ea 04 6b c2 ?? 8d 14 2e 0f b6 5c 2e ?? 32 5c 10 ?? 8b 44 24 ?? 88 5c 28 ?? 41 45 75 de } //20
		$a_03_1 = {89 34 24 c7 44 24 ?? ?? ?? 00 00 c7 44 24 ?? ?? ?? 00 00 ff 15 ?? ?? ?? ?? eb 0c b9 ff ff ff ff eb 10 b8 ff ff ff ff 89 c6 57 ff 15 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}