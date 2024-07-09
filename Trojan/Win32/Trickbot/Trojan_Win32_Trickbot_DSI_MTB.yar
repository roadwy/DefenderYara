
rule Trojan_Win32_Trickbot_DSI_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DSI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 f1 8b 45 ?? 0f be 0c 10 8b 55 ?? 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d ?? 88 81 ?? ?? ?? ?? 81 7d ?? 04 2a 00 00 73 90 09 0a 00 8b 45 ?? 33 d2 b9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}