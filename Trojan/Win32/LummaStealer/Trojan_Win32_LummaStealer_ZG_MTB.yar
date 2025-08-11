
rule Trojan_Win32_LummaStealer_ZG_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 74 da 6d 39 bf eb 69 b8 60 2f 1f 52 90 f4 28 7e 99 53 e0 d8 bc c4 50 2c 7d 84 d5 56 52 f4 42 ce 3c 7c b7 bc 44 c2 7c bb 64 50 90 c9 c0 e7 25 ca 0c a0 f8 ce 83 79 3d 6f f4 18 13 62 2d 37 bc 10 f2 8d 41 0b e1 4a f0 0c 6c 42 d4 73 0f d9 5b 5d f4 4e 6e 7e 6a 1b 13 3c 87 72 7d cb e9 10 88 2f 5a db 81 ac fc 96 7b 56 70 e5 a8 ea c7 3f dd 7f 22 34 6b 48 95 21 c7 d4 fd 4d f6 7e 41 91 4d ca f1 16 5b d3 e2 31 0f 74 6e dc 5e bd 2c 11 17 29 8e 85 f2 1f 34 d9 9e 84 f3 47 2d 19 4b da db 4f c6 a3 5c 87 d3 64 e0 f1 95 99 8e bf 35 86 ff d9 35 c6 96 e1 18 d0 2d 81 4b b0 59 fb c8 d2 0a ab ae 20 9d 58 83 80 2d d6 7f d8 83 da 50 63 b8 df 06 28 4b 2c f4 6d eb ea c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}