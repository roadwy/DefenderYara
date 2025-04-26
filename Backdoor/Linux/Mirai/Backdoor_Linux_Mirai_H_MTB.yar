
rule Backdoor_Linux_Mirai_H_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.H!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {00 10 a0 e3 04 20 a0 e3 00 00 95 e5 e1 06 00 eb 09 20 a0 e3 00 00 95 e5 f0 14 9f e5 e4 06 00 eb 00 10 95 e5 0f 00 a0 e3 95 12 00 eb e0 14 9f e5 15 20 a0 e3 01 00 a0 e3 f5 12 00 eb 35 12 00 eb 00 00 50 e3 24 01 00 ca } //1
		$a_00_1 = {10 40 2d e9 2f 00 a0 e3 fc 42 9f e5 fc 12 9f e5 15 20 a0 e3 e6 ff ff eb 2b 00 a0 e3 f0 12 9f e5 12 20 a0 e3 e2 ff ff eb 04 10 a0 e1 30 00 a0 e3 0b 20 a0 e3 de ff ff eb 01 00 a0 e3 d4 12 9f e5 0e 20 a0 e3 da ff ff eb 02 00 a0 e3 c8 12 9f e5 07 20 a0 e3 d6 ff ff eb 03 00 a0 e3 bc 12 9f e5 05 20 a0 e3 d2 ff ff eb 04 00 a0 e3 00 20 a0 e1 ac 12 9f e5 ce ff ff eb 05 00 a0 e3 a4 12 9f e5 09 20 a0 e3 ca ff ff eb 07 00 a0 e3 98 12 9f e5 98 22 9f e5 c6 ff ff eb 08 00 a0 e3 90 12 9f e5 11 20 a0 e3 c2 ff ff eb 09 00 a0 e3 84 12 9f e5 0c 20 a0 e3 be ff ff eb 04 10 a0 e1 06 00 a0 e3 0b 20 a0 e3 ba ff ff eb } //1
		$a_00_2 = {77 35 71 36 68 65 33 64 62 72 73 67 6d 63 6c 6b 69 75 34 74 6f 31 38 6e 70 61 76 6a 37 30 32 66 } //1 w5q6he3dbrsgmclkiu4to18npavj702f
		$a_00_3 = {2f 74 6d 70 2f 6d 69 72 61 69 } //1 /tmp/mirai
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}