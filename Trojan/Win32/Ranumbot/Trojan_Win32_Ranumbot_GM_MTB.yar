
rule Trojan_Win32_Ranumbot_GM_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c6 33 c8 8d ?? 24 ?? ?? ?? ?? 89 ?? 24 ?? e8 ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 83 ?? 01 90 0a 50 00 8b ?? c1 ?? 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ff ff ff ff 89 ?? 24 ?? 8b ?? 24 ?? ?? 00 00 01 ?? 24 ?? 8b ?? 24 ?? 8b ?? 24 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}