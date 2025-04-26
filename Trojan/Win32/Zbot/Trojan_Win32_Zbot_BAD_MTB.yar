
rule Trojan_Win32_Zbot_BAD_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 4d f8 8b 55 14 8b 45 0c 03 02 8b 4d f8 8b 94 08 ?? ?? ?? ?? 03 55 10 8b 45 14 8b 4d 0c 03 08 8b 45 f8 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}
rule Trojan_Win32_Zbot_BAD_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 44 24 10 8d 4c 24 20 50 51 6a 00 6a 00 6a 0c 6a 00 6a 00 8d 94 24 84 01 00 00 6a 00 52 6a 00 ff 15 40 20 40 00 85 c0 74 28 8b 44 24 10 6a 40 } //2
		$a_01_1 = {15 b4 20 40 00 56 ff 15 b8 20 40 00 57 ff 15 bc 20 40 00 8b b4 24 48 02 00 00 8d 54 24 30 56 52 ff 15 c0 20 40 00 6a 06 56 ff 15 c4 20 40 00 8d 44 24 30 50 ff 15 c8 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}