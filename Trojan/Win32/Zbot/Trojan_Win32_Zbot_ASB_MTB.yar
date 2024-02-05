
rule Trojan_Win32_Zbot_ASB_MTB{
	meta:
		description = "Trojan:Win32/Zbot.ASB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 1f f9 61 f7 90 99 a8 28 fd 96 e3 37 66 11 ac f9 7d 9d 29 76 1b 38 da ae 14 a8 66 c3 39 e7 97 74 ff 7a d8 5e 85 d1 90 11 c7 03 a8 17 88 90 f4 2d f5 df 10 7d a5 14 9f c9 21 6a f7 49 cf 70 23 fd 80 4d ef 6d 11 02 } //02 00 
		$a_01_1 = {29 a1 73 00 d2 1e 11 e7 ff 6c ae 35 89 ff 5d 0d 2e f6 e9 78 26 20 4c f7 d2 51 9f ee 52 b0 1b 64 d6 ff aa 5e 23 51 a5 19 00 3a c6 16 c6 12 06 85 49 ff e3 28 6f b0 a6 65 51 e8 a9 d9 92 d4 0a 96 d9 1b 5c eb 96 30 47 } //01 00 
		$a_01_2 = {e0 00 0f 01 0b 01 02 32 00 40 03 00 00 2e 00 00 00 00 00 00 00 10 00 00 00 10 00 00 00 50 03 } //01 00 
		$a_01_3 = {2e 76 6d 70 30 } //01 00 
		$a_01_4 = {2e 76 6d 70 31 } //01 00 
		$a_01_5 = {2e 76 6d 70 32 } //00 00 
	condition:
		any of ($a_*)
 
}