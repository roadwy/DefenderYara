
rule Trojan_Win32_FlyStudio_DT_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.DT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 0d 32 d3 cf 78 98 63 3d 6e d7 33 40 21 ea 5e 67 06 8c 7c 83 f7 71 e2 cd 49 83 2b 2f 49 2e d8 73 ce 0c ed be 7e 19 ac 0f f9 99 7c c2 4f 7e e4 d7 da f6 af ba 05 78 } //01 00 
		$a_01_1 = {b1 b2 a7 0a e5 a4 14 f1 8f c1 6c d8 1e e7 90 bc 23 32 de 08 c9 bf 90 e5 bf 57 ca 5a b0 37 e6 30 01 dd 5d 3f 1a ac 44 12 c3 31 } //01 00 
		$a_01_2 = {c0 53 f8 e3 e0 ed d6 37 8c f8 d9 2d 0d 3f 24 08 bf 0e 4e 0b 69 ba 38 3e 9b c0 fe 8b f3 7e f7 53 9e 79 29 b7 ea 41 da e5 03 09 44 0d 81 6a d2 83 d2 5d 42 f4 75 b0 } //01 00 
		$a_01_3 = {59 79 30 91 a5 62 31 f9 89 36 93 d8 9f 11 76 0c a5 30 5a 62 93 c7 0e c8 22 b8 74 b2 6a 0a 6a bc 54 38 74 4f e7 41 7f 01 b8 f3 f2 c4 46 45 b1 e0 ab ba 37 89 0c } //00 00 
	condition:
		any of ($a_*)
 
}