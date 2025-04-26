
rule Trojan_Win32_Zbot_DO_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DO!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 db 75 07 8b 1e 83 ee fc 11 db 11 c9 eb 52 29 c9 83 e8 03 72 11 c1 e0 08 8a 06 46 83 f0 ff 74 75 d1 f8 50 5d eb 0b 01 db 75 07 8b 1e 83 ee fc 11 db 72 cc } //1
		$a_01_1 = {8a 06 46 88 07 47 01 db 75 07 8b 1e 83 ee fc 11 db 72 ed } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Zbot_DO_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.DO!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 75 08 bb 0a 00 00 00 8b 4d 0c c1 e9 02 ba 00 00 00 00 8b 45 0c c1 e8 02 2b c1 50 f7 f3 42 42 29 16 33 d2 58 f7 f3 03 14 24 52 81 04 24 21 ec 30 45 5a 31 16 83 c6 04 e2 d4 } //1
		$a_01_1 = {31 19 ad 58 47 22 ed 30 ba f5 12 44 61 07 12 25 55 09 ad 30 13 53 6d 30 45 2d 87 32 13 55 ef 58 45 31 ed 70 f8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}