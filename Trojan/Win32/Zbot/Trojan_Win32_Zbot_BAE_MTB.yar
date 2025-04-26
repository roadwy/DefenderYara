
rule Trojan_Win32_Zbot_BAE_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 40 d4 c1 c8 08 29 f8 83 e8 01 31 ff 4f 21 c7 c1 c7 08 89 03 83 eb fc 83 c6 fc } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
rule Trojan_Win32_Zbot_BAE_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 4d f8 8b 11 03 55 f8 a1 [0-04] 03 45 f8 89 10 8b 4d f8 81 c1 e9 03 00 00 8b 15 [0-04] 03 55 f8 33 0a a1 [0-04] 03 45 f8 89 08 eb } //4
		$a_03_1 = {03 4d f4 8b 01 03 45 f4 03 55 f4 89 02 8b 45 f8 89 45 f0 c7 45 fc 86 7f 00 00 8b 05 [0-04] 89 45 ec 8b 55 08 03 55 f4 8b 02 33 45 ec 8b 4d 08 03 4d f4 89 01 eb } //4
		$a_01_2 = {2e 72 6f 70 66 } //1 .ropf
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4+(#a_01_2  & 1)*1) >=5
 
}