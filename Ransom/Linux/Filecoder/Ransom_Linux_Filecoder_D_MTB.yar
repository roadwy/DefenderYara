
rule Ransom_Linux_Filecoder_D_MTB{
	meta:
		description = "Ransom:Linux/Filecoder.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 c7 e8 90 01 02 ff ff 89 85 4c ff ff ff 8b 85 4c ff ff ff 83 e8 04 48 98 48 8d 50 10 48 8b 85 58 ff ff ff 48 01 d0 48 83 c0 03 48 89 85 60 ff ff ff 48 8b 85 60 ff ff ff 48 8d 35 73 0b 00 00 48 89 c7 e8 90 01 02 ff ff 85 c0 90 00 } //2
		$a_03_1 = {48 89 c1 ba 50 00 00 00 be 01 00 00 00 48 8d 3d 65 09 00 00 e8 90 01 02 ff ff 48 8b 45 98 48 89 c7 e8 90 01 02 ff ff 48 8d 4d a0 48 8d 55 c0 48 8b 75 90 01 02 8b 45 88 48 89 c7 e8 90 01 02 00 00 48 8b 45 88 48 89 c7 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}