
rule Backdoor_Win32_Drixed_G{
	meta:
		description = "Backdoor:Win32/Drixed.G,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 5c d6 10 8b 6c d6 14 33 d8 89 5c 24 [0-01] 33 ef 89 7c 24 [0-01] 89 6c 24 [0-01] 8b e9 89 04 24 8b 74 24 [0-01] 8b 4c 24 [0-01] 8b 5c 24 [0-01] 8b 7c 24 [0-01] 0f be 44 2c [0-01] 85 c0 75 07 46 3b f7 7f 12 eb 08 3b f7 75 04 88 04 19 41 45 83 fd 08 72 e2 eb 9d } //10
		$a_01_1 = {8b d7 c1 ea 02 f7 c7 03 00 00 00 8d 4a 01 0f 45 d1 85 d2 7e 08 31 34 98 43 3b da 7c f8 } //1
		$a_01_2 = {0f 5e 73 82 ea 5e 73 82 ee bf f3 80 43 3d 1c ec 19 37 6e e5 5f 3c ad f6 63 3b b4 bf 5d 6c 64 b2 3f 60 7e 88 5f de 4f f1 67 3b 01 f4 79 01 1f fb 16 3e 07 a7 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}