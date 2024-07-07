
rule Trojan_Win32_Trickbot_SK_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {59 59 ff d7 c6 45 b7 01 eb 90 01 01 55 8b ec 51 53 8b 1d 90 01 04 56 57 33 c0 90 00 } //2
		$a_02_1 = {8b fa 8d 84 3d 90 01 02 ff ff 8a 10 88 16 88 18 0f b6 06 0f b6 d3 03 c2 99 8b f1 f7 fe 8b 85 90 01 02 ff ff 8a 94 15 90 01 02 ff ff 30 10 40 83 bd 90 01 02 ff ff 00 89 85 90 01 02 ff ff 75 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}
rule Trojan_Win32_Trickbot_SK_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec 40 68 90 01 02 00 00 ff 15 90 01 02 00 10 83 3d 90 01 02 00 10 00 74 ec c7 45 90 01 01 57 61 6e 74 c7 45 90 01 01 52 65 6c 65 c7 45 90 01 01 61 73 65 00 ff 35 90 01 02 00 10 6a 00 6a 00 6a 00 6a 00 8d 45 90 01 01 50 ff 35 90 01 02 00 10 ff 15 90 01 02 00 10 90 00 } //2
		$a_00_1 = {51 8b c6 46 8b 0f 8b 00 33 c8 58 88 0f 47 4b 8b c8 75 06 58 2b f0 50 8b d8 49 75 e4 59 58 59 5e 5f 5b } //2
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}