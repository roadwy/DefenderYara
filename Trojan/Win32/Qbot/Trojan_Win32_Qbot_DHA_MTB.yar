
rule Trojan_Win32_Qbot_DHA_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_02_0 = {01 f8 88 c2 0f b6 c2 66 8b 7c 24 ?? 66 69 ff ?? ?? 66 89 7c 24 ?? 8b 7c 24 ?? 8a 14 07 8b 44 24 ?? 35 ?? ?? ?? ?? 8b 7c 24 ?? 8a 34 0f 30 f2 8b 7c 24 ?? 88 14 0f } //1
		$a_02_1 = {01 f8 88 c6 0f b6 c6 88 54 24 ?? c7 44 24 38 ?? ?? ?? ?? 8b 7c 24 ?? 8a 14 0f 8b 7c 24 ?? 8a 34 07 30 d6 8b 44 24 ?? 88 34 08 } //1
		$a_02_2 = {8a 04 03 c7 44 24 ?? ?? ?? ?? ?? c7 44 24 ?? ?? ?? ?? ?? 66 8b 5c 24 ?? 66 33 5c 24 ?? 88 44 24 ?? 8b 44 24 ?? 8a 04 38 66 89 5c 24 ?? 8a 64 24 ?? 30 e0 8b 7c 24 ?? 88 04 0f } //1
		$a_02_3 = {88 04 19 0f b6 14 11 8b 44 24 ?? 35 ?? ?? ?? ?? 01 f2 8b 74 24 ?? 8b 4c 24 ?? 8a 0c 0e 21 fa 8b 7c 24 ?? 8a 2c 17 30 cd 8b 54 24 ?? 8b 74 24 ?? 88 2c 32 } //1
		$a_02_4 = {0f b6 36 03 74 24 ?? 8b 7c 24 ?? 8a 1c 0f 21 c6 32 1c 32 8b 44 24 ?? 35 ?? ?? ?? ?? 8b 4c 24 ?? 89 4c 24 ?? 8b 74 24 ?? 8b 4c 24 ?? 88 1c 31 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=1
 
}