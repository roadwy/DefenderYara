
rule Trojan_Win32_CobaltStrike_ZA_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.ZA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 15 dc 64 07 00 48 8d 44 24 40 48 8b 0d d8 64 07 00 33 db 48 89 5c 24 30 45 33 c9 48 89 5c 24 28 89 5c 24 40 44 8d 43 01 48 89 44 24 20 } //1
		$a_01_1 = {48 f7 e9 48 03 d1 48 c1 fa 18 48 8b fa 48 c1 ef 3f 48 03 fa 49 03 f8 } //1
		$a_01_2 = {b8 0d 00 00 00 66 89 45 8f 48 89 7c 24 20 4c 8d 4d 97 44 8d 40 f4 48 8d 55 8f 49 8b cc } //1
		$a_01_3 = {48 89 7c 24 20 4c 8d 4d 80 45 33 c0 48 8b d7 48 8d 4c 24 58 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}