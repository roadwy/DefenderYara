
rule Trojan_Win32_Zbot_SIBB6_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBB6!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {50 89 c7 be ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 49 8a 1d ?? ?? ?? ?? 0f 31 50 8a 3e 88 3f 47 46 46 50 8a 06 aa 00 5f ff 58 e2 } //1
		$a_02_1 = {66 81 3f 4d 5a 75 ?? 89 fa 03 57 3c 66 81 3a 50 45 75 ?? 89 55 ?? 8b 42 78 03 45 08 89 45 ?? 8b 40 20 03 45 08 89 45 ?? 31 c9 8b 55 90 1b 03 3b 4a 18 7d 3a 8b 5d 90 1b 04 8b 1c 8b 03 5d 08 ff 75 0c 53 e8 ?? ?? ?? ?? 83 f8 01 74 ?? 41 eb ?? 8b 45 90 1b 03 8b 40 24 03 45 08 31 db 66 8b 1c 48 8b 45 90 1b 03 8b 40 1c 03 45 08 8b 04 98 03 45 08 eb } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}