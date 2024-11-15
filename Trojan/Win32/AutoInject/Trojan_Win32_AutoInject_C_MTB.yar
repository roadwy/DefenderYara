
rule Trojan_Win32_AutoInject_C_MTB{
	meta:
		description = "Trojan:Win32/AutoInject.C!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 36 56 a6 df 30 77 1c 5f 2c ca 62 22 c9 ec 35 7e c6 63 63 dd 4c 49 93 4f 65 5c e7 e4 b2 fb f6 be 1f e7 c1 f5 76 81 12 b2 5b 16 a2 9d dc d9 41 d7 eb 43 fd e8 ec a8 65 b9 85 49 82 2a e9 d5 1e e7 0b 13 5a c8 d4 4c bb 0f ed e8 93 9b 5a 39 8a 9a 9c c7 84 63 25 8f a0 dd 77 9d 7e 68 81 df 8f 3d 77 87 73 6e 2d a1 7d 06 9b 19 a1 bc 51 21 16 cd 5f 5d d9 b5 15 0d 6a fb eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}