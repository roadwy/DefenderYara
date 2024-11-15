
rule Ransom_Linux_Cactus_B_MTB{
	meta:
		description = "Ransom:Linux/Cactus.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 b8 48 98 48 03 85 98 fe ff ff 48 89 c7 e8 ec 10 00 00 83 f0 01 84 c0 0f 84 af 02 00 00 0f b6 05 69 a3 34 00 83 f0 01 84 c0 0f 84 a1 02 00 00 48 8b 15 4e a3 34 00 48 8b 05 3f a3 34 00 48 39 c2 0f 83 8a 02 00 00 8b 45 b8 48 98 48 03 85 98 fe ff ff ba 05 00 00 00 } //1
		$a_01_1 = {63 41 63 54 75 53 2e 72 65 61 64 6d 65 2e 74 78 74 } //1 cAcTuS.readme.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}