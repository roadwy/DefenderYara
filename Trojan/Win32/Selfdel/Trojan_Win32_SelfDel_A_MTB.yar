
rule Trojan_Win32_SelfDel_A_MTB{
	meta:
		description = "Trojan:Win32/SelfDel.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {b9 80 81 82 83 c6 45 f4 83 33 d2 39 08 0f 94 c2 23 f2 33 d2 39 08 } //01 00 
		$a_01_1 = {8a 1c 08 80 f3 42 88 19 41 4a 75 f4 5b } //01 00 
		$a_01_2 = {c1 e2 02 2b fa 8a 97 ff f7 ff ff 81 ef 01 08 00 00 41 88 10 40 47 8a 17 88 10 8a 57 01 40 88 10 40 8a 51 fe } //01 00 
		$a_01_3 = {83 7d 0c 23 66 c7 45 dc 5c 00 66 c7 45 de 4d 00 66 c7 45 e0 6f 00 66 c7 45 e2 7a 00 66 c7 45 e4 69 00 66 c7 45 e6 6c 00 66 c7 45 e8 6c 00 66 c7 45 ea 61 00 66 89 75 ec 66 c7 45 f0 2e 00 66 c7 45 f2 65 00 66 c7 45 f4 78 00 } //00 00 
	condition:
		any of ($a_*)
 
}