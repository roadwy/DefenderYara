
rule Trojan_Win32_Zbot_GB_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 13 8b 4d a0 c1 c9 13 03 d9 8b 03 c1 c0 0b 83 e0 05 03 d0 4f 89 16 b9 00 02 00 00 c1 c9 07 03 f1 85 ff 75 ac } //10
		$a_01_1 = {8b c6 c1 e0 10 0b f0 89 35 98 e0 40 00 f7 d6 89 35 9c e0 40 00 5e 5f 5b c9 c3 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}