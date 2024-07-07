
rule Trojan_Win32_Zbot_rbnd_MTB{
	meta:
		description = "Trojan:Win32/Zbot.rbnd!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 70 60 8b 45 fc 83 c0 20 03 f0 8b 3e 83 ee 0c 8b 06 03 7d fc 89 45 f4 83 ee 14 33 d2 8b 5d 0c c3 } //10
		$a_01_1 = {89 15 43 29 06 29 42 33 30 43 03 42 00 36 50 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}