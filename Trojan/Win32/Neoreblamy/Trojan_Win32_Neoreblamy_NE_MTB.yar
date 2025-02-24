
rule Trojan_Win32_Neoreblamy_NE_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {08 44 24 a8 e2 91 93 b6 45 04 dc 52 b4 a8 03 e5 f8 ae dc c5 ed } //2
		$a_01_1 = {0f 94 c2 2b d1 33 c9 3b d0 8b 45 e8 0f 9f c1 33 d2 8b 44 85 b0 3b c1 8b 45 e8 0f 94 c2 33 c9 8b 44 85 b0 3b d0 0f 9c c1 } //1
		$a_01_2 = {5d 13 30 87 f3 35 95 59 89 d4 fa 2c e6 ec 8c ab a5 91 b9 ff 25 bd 20 45 fb } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}