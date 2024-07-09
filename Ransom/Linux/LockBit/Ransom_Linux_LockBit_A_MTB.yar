
rule Ransom_Linux_LockBit_A_MTB{
	meta:
		description = "Ransom:Linux/LockBit.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 e9 41 c1 e1 10 44 31 c8 44 0f b6 8d ?? ?? 42 00 89 cd c1 ed 10 40 0f b6 ed 41 c1 e1 18 44 31 c8 44 0f b6 8d ?? ?? 42 00 41 c1 e1 08 44 31 c8 31 c7 89 82 ?? 00 00 00 83 f0 1b 31 fe 41 89 7a 14 31 f1 41 89 72 18 0f b6 ed } //2
		$a_03_1 = {44 0f b6 c9 45 0f b6 89 ?? ?? 42 00 41 c1 e1 18 44 31 c8 41 89 c9 41 c1 e9 10 45 0f b6 c9 45 0f b6 89 ?? ?? 42 00 41 c1 e1 08 44 31 c8 31 c7 89 82 a0 00 00 00 83 f0 36 31 fe 41 89 78 14 89 f2 41 89 70 18 31 ca 0f b6 ce } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}