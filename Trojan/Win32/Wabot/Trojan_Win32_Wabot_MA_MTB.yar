
rule Trojan_Win32_Wabot_MA_MTB{
	meta:
		description = "Trojan:Win32/Wabot.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {be d6 ae f1 81 ed e5 5b de 26 d8 5b 9f 1a aa 2a 4f 67 8d 12 bd 96 78 f3 3a c9 a5 a1 31 2d 0f 54 fd 89 73 8e 0e 77 84 1e c3 06 5c 3e 8d e1 5a df } //10
		$a_01_1 = {e4 88 09 4e 5b b7 58 67 7e 1b 7c 33 b6 69 e9 50 b1 94 fe 8a a9 b7 c9 77 23 2d ae e0 b5 eb 55 28 b6 5e 38 1d f4 64 a2 d2 c8 20 0e 86 25 be 34 ad 83 74 26 90 bc 41 50 39 3c 44 50 80 14 ab d4 83 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}