
rule Ransom_Linux_Cactus_A_MTB{
	meta:
		description = "Ransom:Linux/Cactus.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 8b 65 b0 8b 45 b0 48 98 48 c1 e0 03 48 05 40 36 75 00 48 89 c7 e8 45 aa ff ff 48 8b 95 38 fe ff ff 49 63 cc 48 89 04 ca 83 45 b0 01 8b 05 b5 8d 33 00 39 45 b0 0f 9c c0 84 c0 75 c3 } //1
		$a_01_1 = {8b 45 b4 48 98 48 03 85 98 fe ff ff ba 05 00 00 00 be 00 00 00 00 48 89 c7 e8 f8 11 00 00 83 45 b4 01 8b 05 18 a9 34 00 39 45 b4 0f 9c c0 84 c0 75 ce } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}