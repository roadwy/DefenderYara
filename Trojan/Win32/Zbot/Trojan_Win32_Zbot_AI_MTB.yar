
rule Trojan_Win32_Zbot_AI_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 f8 8a 54 32 ff 80 e2 0a 32 c2 88 45 f3 8d 45 fc e8 [0-04] 8b 55 fc 8a 54 1a ff 80 e2 f0 80 e2 f0 8a 4d f3 02 d1 88 54 18 ff 46 8b 45 f8 e8 [0-04] 3b f0 7e ?? be 01 00 00 00 43 4f 75 } //2
		$a_01_1 = {88 14 18 33 db 8a 98 00 01 00 00 02 14 18 81 e2 ff 00 00 00 8a 14 10 32 16 88 11 41 46 ff 4d fc 75 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}