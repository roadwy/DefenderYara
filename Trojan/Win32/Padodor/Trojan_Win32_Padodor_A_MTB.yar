
rule Trojan_Win32_Padodor_A_MTB{
	meta:
		description = "Trojan:Win32/Padodor.A!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {21 6b 86 ed a3 13 ea 1b 4b e2 a9 e3 21 6b 86 ee a3 07 ea 1b 4b e2 a9 e7 21 6b 86 ef a3 0b ea 1b 4b e2 a9 ef 23 75 dc 1b 5b 94 99 e3 a3 2f ea 1b 4b c8 e4 2b 4b 7b 84 07 7b 6b fc e4 3e 97 04 29 4d 6b ec b8 4f 5b ec 0b 23 77 dc 1b 5b 94 99 ef a3 4b ea 1b 4b e8 28 2b e8 67 dc 1b 5b e0 d1 1f 7b 6b fc 12 b4 1f e7 71 4b 3c 04 41 4d 6b ec 98 8f 63 67 26 47 5b ec 0b } //1
		$a_01_1 = {55 f8 bd c5 11 68 ac 44 d6 0d 75 04 3d 25 4a 41 9e cb f7 44 57 cb 12 1f d6 3c df 44 80 d4 d3 b9 29 c3 36 80 de 0d 75 1b 88 67 e8 87 83 b5 50 c5 3a 2c b4 44 d6 6f e3 13 5d 49 bd fb 16 6c 32 79 5f c4 b4 bc 5f fb 73 c1 25 c2 4a bb d6 c3 b0 0c 21 7e b5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}