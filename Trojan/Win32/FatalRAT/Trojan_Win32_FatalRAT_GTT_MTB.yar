
rule Trojan_Win32_FatalRAT_GTT_MTB{
	meta:
		description = "Trojan:Win32/FatalRAT.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 e4 ?? 81 ec ?? ?? ?? ?? a1 ?? ?? ?? ?? 33 c4 89 84 24 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 8d 44 24 ?? 33 f6 50 6a 40 56 56 89 74 24 ?? ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}