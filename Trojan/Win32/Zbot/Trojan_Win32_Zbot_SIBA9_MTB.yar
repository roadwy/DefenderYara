
rule Trojan_Win32_Zbot_SIBA9_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBA9!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d 08 03 4d ?? 8b 11 03 55 90 1b 00 8b 45 08 03 45 90 1b 00 89 10 [0-0a] 8b 4d 90 1b 00 81 c1 ?? ?? ?? ?? 8b 55 08 03 55 90 1b 00 33 0a 8b 45 08 03 45 90 1b 00 89 08 [0-0a] 90 18 8b 45 90 1b 00 83 c0 04 89 45 90 1b 00 8b 4d 90 1b 00 3b 4d 0c 73 ?? [0-10] 83 7d 90 1b 00 00 90 18 8b 4d 08 03 4d 90 1b 00 8b 11 03 55 90 1b 00 8b 45 08 03 45 90 1b 00 89 10 [0-0a] 8b 4d 90 1b 00 81 c1 90 1b 05 8b 55 08 03 55 90 1b 00 33 0a 8b 45 08 03 45 90 1b 00 89 08 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}