
rule Ransom_Linux_Lockbit_CE_MTB{
	meta:
		description = "Ransom:Linux/Lockbit.CE!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 7c 24 0c e8 33 ?? ?? ?? 31 c9 31 d2 89 c6 bf 10 00 00 00 31 c0 e8 81 } //1
		$a_03_1 = {48 89 f8 48 89 f9 8a 11 48 ff c1 83 f2 ?? 88 51 ff 84 d2 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}