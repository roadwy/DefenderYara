
rule Trojan_Win32_Trickbot_GI_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.GI!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 73 24 8b 45 fc 33 d2 f7 75 14 8b 45 10 0f be 0c 10 8b 55 08 03 55 fc 0f be 02 33 c1 8b 4d 08 03 4d fc 88 01 eb cb } //1
		$a_01_1 = {b9 6b 00 00 00 66 89 8d 6c ff ff ff ba 65 00 00 00 66 89 95 6e ff ff ff b8 72 00 00 00 66 89 85 70 ff ff ff b9 6e 00 00 00 66 89 8d 72 ff ff ff ba 65 00 00 00 66 89 95 74 ff ff ff b8 6c 00 00 00 66 89 85 76 ff ff ff b9 33 00 00 00 66 89 8d 78 ff ff ff ba 32 00 00 00 66 89 95 7a ff ff ff b8 2e 00 00 00 66 89 85 7c ff ff ff b9 64 00 00 00 66 89 8d 7e ff ff ff ba 6c 00 00 00 66 89 55 80 b8 6c 00 00 00 66 89 45 82 33 c9 66 89 4d 84 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}