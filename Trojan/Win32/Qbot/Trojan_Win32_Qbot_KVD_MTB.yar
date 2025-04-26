
rule Trojan_Win32_Qbot_KVD_MTB{
	meta:
		description = "Trojan:Win32/Qbot.KVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {0f b6 11 8b 45 ?? 03 85 ?? ?? ?? ?? 0f b6 08 33 d1 8b 45 ?? 88 10 } //2
		$a_02_1 = {80 ca dd 88 54 24 ?? 8b 74 24 ?? 88 04 0e 90 09 0c 00 8a 44 24 ?? 8b 4c 24 ?? 8a 54 24 } //2
		$a_02_2 = {8b 45 14 03 85 ?? fe ff ff 8b 08 2b 8d ?? fe ff ff 8b 55 14 03 95 ?? fe ff ff 89 0a eb } //2
		$a_02_3 = {8b c6 f7 f7 8b 44 24 0c 8a 04 02 30 01 46 3b 74 24 ?? 75 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2) >=2
 
}