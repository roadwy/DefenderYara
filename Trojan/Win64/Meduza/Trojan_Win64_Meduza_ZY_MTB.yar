
rule Trojan_Win64_Meduza_ZY_MTB{
	meta:
		description = "Trojan:Win64/Meduza.ZY!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {38 65 03 fa 61 03 38 c1 02 60 69 03 44 6d 03 c2 79 03 c8 85 03 6d 02 89 03 3e 8d 03 22 95 03 70 99 03 42 9d 03 26 99 03 1a a1 03 c6 a9 03 6c 99 03 94 b1 03 2c 99 03 20 b5 03 c6 bd 03 84 99 03 15 04 d5 03 5a 99 03 1c 95 03 2c 89 03 1c 85 03 3e 79 03 a4 6d 03 a4 c1 02 e4 b5 02 8a a9 02 8a a1 02 88 8c 18 38 b2 06 b2 00 3d 02 06 0c 10 0c 06 0c 38 0c 10 3a 3e 2e 4c 20 56 0c 8c 0c 38 3a 9c 0c ac 00 ca 40 cb 62 0b e0 cc 24 ee 25 4b 80 c8 c0 cc 20 cb 61 ea 82 ea 43 af a0 cf e2 e1 90 22 02 90 20 c3 10 24 e7 10 25 41 d0 20 c1 90 21 e3 10 20 c8 c0 cf a3 a9 c0 ca 00 ca 40 cb 62 0b e0 cc 24 ee 25 4b 80 c8 c0 cc 20 cb 61 ea 82 ea 43 aa 50 22 ec 90 22 cd 02 24 e9 02 20 fd 02 0c 65 03 20 69 03 24 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}