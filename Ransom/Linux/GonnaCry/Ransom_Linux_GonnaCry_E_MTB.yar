
rule Ransom_Linux_GonnaCry_E_MTB{
	meta:
		description = "Ransom:Linux/GonnaCry.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f3 0f 1e fa 55 48 89 e5 53 48 81 ec 68 05 00 00 48 89 bd 98 fa ff ff 64 48 8b 04 25 28 00 00 00 48 89 45 e8 31 c0 48 8d 85 b0 fa ff ff 48 89 85 a0 fa ff ff 48 8d 05 cd 3d 01 00 48 89 85 a8 fa ff ff } //1
		$a_01_1 = {48 8b 85 a8 fa ff ff 48 83 c0 01 48 89 85 a8 fa ff ff 48 8b 85 a0 fa ff ff 48 8b 10 48 8b 85 a0 fa ff ff 48 83 e8 08 48 8b 00 48 39 c2 0f 95 c1 48 8b 85 a0 fa ff ff 48 8d 50 f8 0f b6 c1 89 02 48 8b 85 a0 fa ff ff 48 83 e8 08 48 89 85 a0 fa ff ff e9 bf 12 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}