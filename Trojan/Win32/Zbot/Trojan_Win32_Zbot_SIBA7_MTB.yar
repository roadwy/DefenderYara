
rule Trojan_Win32_Zbot_SIBA7_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBA7!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 08 03 4d ?? 8b 55 ?? 89 0a 8b 45 ?? 8b 08 89 4d ?? 8b 15 ?? ?? ?? ?? 52 8b 45 90 1b 03 50 e8 ?? ?? ?? ?? 83 c4 08 89 45 ?? 8b 4d 90 1b 02 8b 55 90 1b 07 89 11 90 18 8b 45 90 1b 00 83 c0 ?? 89 45 90 1b 00 8b 4d 90 1b 00 3b 4d ?? 0f 83 ?? ?? ?? ?? [0-1a] 8b 55 90 1b 00 81 c2 ?? ?? ?? ?? 89 15 90 1b 04 [0-0a] 8b 45 ?? 03 45 90 1b 00 89 45 90 1b 01 [0-1a] 8b 4d 90 1b 01 89 4d 90 1b 02 8b 15 90 1b 04 [0-10] 8b 45 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}