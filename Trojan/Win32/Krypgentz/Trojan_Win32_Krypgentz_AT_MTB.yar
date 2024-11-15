
rule Trojan_Win32_Krypgentz_AT_MTB{
	meta:
		description = "Trojan:Win32/Krypgentz.AT!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 38 19 75 ed 8d 85 64 fe ff ff 50 8d 85 d4 ed ff ff 50 e8 43 1e 00 00 59 59 3b c3 74 3e 6a 2c 50 e8 75 1d 00 00 59 3b c3 59 74 30 40 8b c8 38 13 87 40 e8 03 93 b7 50 48 81 9e b0 14 13 81 97 5f 26 a0 a5 35 0e 82 31 b0 00 00 83 c4 0c 83 f8 02 74 1d 83 f8 03 74 18 83 f8 01 74 13 8d 45 fc 50 e8 98 fe ff ff 80 7d fc 06 59 1b c0 83 c0 03 5b c9 c3 33 c0 6a 00 39 44 24 08 68 00 } //1
		$a_01_1 = {26 3b c3 7d 22 84 c9 74 0a 8a 07 47 84 c0 75 f9 20 47 fe 8d 45 f0 6a 01 50 53 ff 75 0c e8 e5 fe ff ff 83 c4 10 eb 15 8d 45 f0 6a 01 50 ff 75 14 53 ff 75 0c e8 b7 fd ff ff 83 c4 14 5f 5e 5b c9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}