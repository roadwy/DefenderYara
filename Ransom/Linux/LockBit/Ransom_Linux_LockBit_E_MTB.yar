
rule Ransom_Linux_LockBit_E_MTB{
	meta:
		description = "Ransom:Linux/LockBit.E!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {66 66 2e 0f 1f 84 00 00 00 00 00 0f b7 77 38 4c 8b 97 a7 00 00 00 41 b9 02 00 00 00 0f af 77 3a 45 8b 82 ec 01 00 00 44 89 c0 c1 ee 02 66 0f 1f 44 00 00 83 c0 01 39 c6 41 0f 42 c1 44 39 c0 74 14 48 8b 57 46 89 c1 8b 14 8a 85 d2 75 e5 41 89 82 ec 01 00 00 } //1
		$a_00_1 = {0f b6 47 77 0f b7 57 38 83 ee 02 48 0f af c2 48 0f af c6 48 03 47 5e c3 0f 1f 84 00 00 00 00 00 0f b6 47 77 0f b7 57 38 83 ee 02 48 0f af c2 48 0f af c6 48 03 47 5e c3 } //1
		$a_00_2 = {31 c0 48 85 ff 74 1c 66 83 3f 00 48 89 fa 74 13 48 83 c2 02 66 83 3a 00 75 f6 48 89 d0 48 29 f8 48 d1 f8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}