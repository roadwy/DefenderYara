
rule Trojan_Win32_Zbot_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {39 d2 74 01 90 01 01 31 1f 81 c7 04 00 00 00 81 c1 90 01 04 21 f6 39 d7 75 e7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zbot_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c2 89 c1 89 f8 83 ca 01 89 55 e8 99 f7 7d e8 01 c1 8b 45 cc 03 4d 08 09 f8 03 45 08 ff 4d e4 8a 10 88 55 e8 8a 11 88 10 8a 45 e8 88 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zbot_RPZ_MTB_3{
	meta:
		description = "Trojan:Win32/Zbot.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 dd 08 c6 45 de 2b c6 45 df 08 c6 45 e0 5c c6 45 e1 08 c6 45 e2 31 c6 45 e3 08 c6 45 e4 5c c6 45 e5 08 c6 45 e6 52 c6 45 e7 08 c6 45 e8 31 c6 45 e9 08 c6 45 ea 3f c6 45 eb 08 c6 45 ec 31 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}