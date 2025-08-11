
rule Ransom_Win64_Anubis_C_MTB{
	meta:
		description = "Ransom:Win64/Anubis.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {49 3b 66 10 76 33 48 83 ec 28 48 89 6c 24 20 48 8d 6c 24 20 48 8d 05 94 4e 07 00 bb 12 00 00 00 31 c9 31 ff e8 ?? ?? ?? ?? 48 85 db 0f 94 c0 48 8b 6c 24 20 } //2
		$a_03_1 = {4c 89 d8 48 8d 1d 12 0d 07 00 b9 05 00 00 00 e8 ?? ?? ?? ?? 48 8b 4c 24 38 48 8b 54 24 28 4c 8b 44 24 58 4c 8b 4c 24 48 4c 8b 54 24 30 4c 8b 5c 24 50 89 c3 48 8b 44 24 40 84 db 74 } //2
		$a_01_2 = {2e 61 6e 75 62 69 73 } //1 .anubis
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}