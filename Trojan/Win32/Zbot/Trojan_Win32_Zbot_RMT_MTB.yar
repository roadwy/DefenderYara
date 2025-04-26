
rule Trojan_Win32_Zbot_RMT_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 f3 42 c0 de e5 15 65 ce 0c 79 b2 59 35 fa 31 84 76 81 ba 5f 10 8f 14 55 98 9b ec e1 e4 } //10
		$a_01_1 = {8b 06 8a e9 32 c5 fe c1 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}