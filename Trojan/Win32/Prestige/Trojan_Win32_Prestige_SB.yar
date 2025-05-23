
rule Trojan_Win32_Prestige_SB{
	meta:
		description = "Trojan:Win32/Prestige.SB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0a 00 00 "
		
	strings :
		$a_01_0 = {89 46 48 8b 7a 4c 89 7e 4c 83 7a 4c 10 77 06 } //1
		$a_03_1 = {03 f3 c7 06 65 2b 30 30 8d 46 04 33 d2 e9 ?? ?? ?? ?? 8b d1 c7 45 c4 09 00 00 00 } //1
		$a_01_2 = {83 f8 26 76 03 6a 26 58 0f b6 0c 85 be 53 47 00 0f b6 34 85 bf 53 47 00 } //1
		$a_01_3 = {b9 fe 02 00 00 3b c1 0f 4f c1 8d 8d ec fc ff ff 50 89 85 e8 fc ff ff e8 } //1
		$a_01_4 = {3b f0 73 0a 8b c6 89 74 24 10 89 7c 24 14 50 ff 75 08 } //1
		$a_03_5 = {8d 45 fc 50 8b d6 e8 ?? ?? ?? ?? 8b 75 08 8b f8 59 } //1
		$a_01_6 = {8b f2 57 8b f9 8d 4e 02 66 8b 06 83 c6 02 66 85 c0 } //1
		$a_01_7 = {85 c0 74 0c 8d 43 2c 89 45 f8 8b 00 } //1
		$a_01_8 = {89 45 d8 8b 45 e8 5e 13 ce f7 65 e0 6a 00 89 45 ec } //1
		$a_03_9 = {59 c3 8b 4c 24 0c 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 44 24 0c 5e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_03_9  & 1)*1) >=7
 
}