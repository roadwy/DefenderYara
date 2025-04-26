
rule Trojan_Win32_Trickbot_GD_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 08 0f b6 55 ?? 33 ca 8b 45 ?? 2b 45 ?? 0f b6 d0 81 e2 e0 00 00 00 33 ca 8b 45 ?? 88 08 8b 4d ?? 03 4d ?? 89 4d ?? eb 90 0a 3c 00 8b 55 ?? 3b 55 ?? 73 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}