
rule Ransom_Linux_LockBit_D_MTB{
	meta:
		description = "Ransom:Linux/LockBit.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 c8 31 d2 4c 01 e1 48 f7 f3 31 d2 48 89 c6 48 89 c8 48 0f af f3 48 29 f0 48 89 37 48 f7 f3 31 d2 49 89 c1 4c 89 d0 48 f7 f3 49 39 c1 4c 0f 47 c8 49 83 c0 01 44 89 4f 08 48 83 c7 0c 4c 39 45 00 } //2
		$a_01_1 = {0f b6 f7 89 ff 45 33 01 45 89 ed 4c 89 f0 44 33 04 b5 a0 6a 43 00 89 ce 0f b6 c4 c1 ee 10 40 0f b6 f6 44 33 04 b5 a0 6e 43 00 41 0f b6 f6 8b 34 b5 a0 66 43 00 33 34 bd a0 72 43 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}