
rule Trojan_Win32_Trickbot_IG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.IG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 55 08 03 55 [0-08] 8b 4d ?? 03 4d [0-14] 33 ?? 8b ?? ?? 03 ?? ?? 88 ?? e9 90 0a 9b 00 8b 55 ?? 83 c2 01 89 55 ?? 8b 45 ?? 3b 45 [0-0a] 83 c1 01 81 e1 ?? ?? ?? ?? 89 4d ?? 8b 55 [0-0c] 89 45 ?? 8b 4d ?? 03 4d ?? 81 e1 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}