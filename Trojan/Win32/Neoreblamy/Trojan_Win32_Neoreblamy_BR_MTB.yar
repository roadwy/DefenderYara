
rule Trojan_Win32_Neoreblamy_BR_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {59 33 d2 8b c6 f7 f1 8b 45 08 ff 34 ?? ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 59 59 3b f7 72 } //6
		$a_01_1 = {55 8b ec 53 56 57 8d 3c 09 33 f6 } //2
		$a_01_2 = {40 6a 04 59 d1 e1 89 84 0d } //2
		$a_03_3 = {0f b6 94 15 ?? ?? ff ff 0f be 54 15 ?? 23 ca 2b c1 8b 4d ?? 0f b6 8c 0d ?? ?? ff ff 88 44 0d } //6
		$a_01_4 = {8b 45 fc 8b 00 40 8b 4d fc 89 01 8b 45 fc 83 38 00 7f } //2
		$a_03_5 = {ff 6b 89 85 ?? ?? ff ff 6b 85 ?? ?? ff ff 6c 89 85 } //2
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_03_3  & 1)*6+(#a_01_4  & 1)*2+(#a_03_5  & 1)*2) >=10
 
}