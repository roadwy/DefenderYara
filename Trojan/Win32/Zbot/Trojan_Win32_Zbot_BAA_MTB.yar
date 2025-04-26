
rule Trojan_Win32_Zbot_BAA_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 94 06 32 09 00 00 88 14 08 8b 7c 24 10 40 3b c7 72 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}
rule Trojan_Win32_Zbot_BAA_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 33 f8 83 d3 ?? f7 d6 83 c6 ?? 01 d6 83 ee ?? 29 d2 31 f2 89 31 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}
rule Trojan_Win32_Zbot_BAA_MTB_3{
	meta:
		description = "Trojan:Win32/Zbot.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 8b 8d 68 dc ff ff 51 6a 00 ff 15 [0-04] 89 85 1c dc ff ff 6a 00 8d 95 40 dc ff ff 52 6a 0e 8d 85 44 dc ff ff 50 8b 8d 20 dc ff ff 51 ff 15 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}