
rule Trojan_Win32_Ursnif_ibt{
	meta:
		description = "Trojan:Win32/Ursnif!ibt,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 81 58 6e 43 00 6b ba 01 00 00 00 6b c2 0a c6 80 58 6e 43 00 6c b9 01 00 00 00 6b d1 06 c6 82 58 6e 43 00 33 b8 01 00 00 00 6b c8 03 c6 81 58 6e 43 00 6e ba 01 00 00 00 c1 e2 02 c6 82 58 6e 43 00 65 b8 01 00 00 00 6b c8 07 c6 81 58 6e 43 00 32 ba 01 00 00 00 6b c2 05 c6 80 58 6e 43 00 6c b9 01 00 00 00 c1 e1 00 c6 81 58 6e 43 00 65 } //1
		$a_01_1 = {6a 00 6a 00 6a 00 ff 15 00 90 41 00 6a 00 6a 00 ff 15 04 90 41 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 10 90 41 00 8d 4d b0 51 6a 00 6a 00 ff 15 18 90 41 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 14 90 41 00 } //1
		$a_01_2 = {c7 45 ac ff ff ff ff c7 45 64 c8 d2 e0 45 c7 45 58 b4 6f f8 23 c7 45 60 e5 a0 b3 0d c7 45 5c cf 8c 67 0c c7 45 48 f7 37 08 05 c7 45 50 3f 26 49 52 c7 45 30 9d fc 30 3c c7 45 4c 09 b0 b7 5e c7 45 24 5c b6 b6 52 c7 45 54 4f fd e6 2b c7 45 3c 4b 7d c7 60 c7 45 20 c5 f7 e0 57 c7 45 40 f6 9c 89 0c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}