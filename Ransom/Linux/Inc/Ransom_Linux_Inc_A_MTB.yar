
rule Ransom_Linux_Inc_A_MTB{
	meta:
		description = "Ransom:Linux/Inc.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 55 f4 48 63 d2 48 89 10 8b 45 fc 48 c1 e0 03 48 03 45 e0 8b 55 fc 48 c1 e2 03 48 03 55 e0 48 8b 12 33 55 f4 48 63 d2 } //2
		$a_01_1 = {8b 45 fc 48 c1 e0 03 48 03 45 e8 48 8b 00 89 c2 8b 45 fc 48 c1 e0 03 48 03 45 e0 48 8b 00 31 d0 23 45 f8 89 45 f4 8b 45 fc 48 c1 e0 03 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}