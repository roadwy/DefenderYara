
rule Trojan_Win32_Trickbot_EC_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 19 0f be 14 08 8b c3 03 f2 25 ff 00 00 00 33 d2 03 c6 f7 f7 8b f2 8a 04 2e 88 01 8b 44 ?? 18 88 1c 2e 8b 3d 28 81 01 10 40 41 3b c7 } //1
		$a_02_1 = {8d 46 01 33 d2 f7 35 ?? ?? ?? ?? 8b f2 33 d2 8a 1c 0e 8b c3 88 5c 24 ?? 25 ff 00 00 00 03 c7 f7 35 ?? ?? ?? ?? 8b fa 8b 54 24 14 81 e2 ff 00 00 00 8a 04 0f 88 04 0e 33 c0 88 1c 0f 8a 04 0e 03 c2 33 d2 f7 35 28 81 01 10 a1 ?? ?? ?? ?? 2b d0 8b 44 24 ?? 8a 14 0a 8a 1c 28 32 da 88 1c 28 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}