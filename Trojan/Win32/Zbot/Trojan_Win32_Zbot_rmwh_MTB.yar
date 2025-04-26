
rule Trojan_Win32_Zbot_rmwh_MTB{
	meta:
		description = "Trojan:Win32/Zbot.rmwh!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 06 8a e9 32 c5 fe c1 } //10
		$a_02_1 = {8b 3e 83 ee ?? 8b 06 03 7d fc 89 45 f4 83 ee ?? 33 d2 8b 5d 0c c3 } //10
		$a_01_2 = {53 23 0e 30 48 61 96 8a 54 fb a1 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_02_1  & 1)*10+(#a_01_2  & 1)*10) >=20
 
}