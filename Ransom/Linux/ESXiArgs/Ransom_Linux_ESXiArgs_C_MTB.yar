
rule Ransom_Linux_ESXiArgs_C_MTB{
	meta:
		description = "Ransom:Linux/ESXiArgs.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_00_0 = {8b 45 a4 69 c0 07 53 65 54 89 45 a8 8b 45 a8 c1 c8 19 89 45 d0 8b 45 fc 89 45 b8 8b 45 fc 89 c2 c1 e2 08 8b 45 fc c1 e8 18 89 c0 8b 04 85 e0 92 60 00 89 d1 31 c1 8b 45 f0 89 c2 c1 ea 08 0f b6 45 f0 89 c0 8b 04 85 e0 96 60 00 } //5
	condition:
		((#a_00_0  & 1)*5) >=5
 
}