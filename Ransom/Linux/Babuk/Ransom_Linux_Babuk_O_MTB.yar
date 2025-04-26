
rule Ransom_Linux_Babuk_O_MTB{
	meta:
		description = "Ransom:Linux/Babuk.O!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 48 08 48 8b 8c 24 90 00 00 00 48 89 48 18 48 89 50 10 e8 b6 ff f8 ff 48 8b 4c 24 70 48 ff 01 } //1
		$a_01_1 = {55 48 89 e5 48 83 ec 10 48 8b 7c 24 20 48 8b 74 24 28 48 8b 54 24 30 48 8b 05 f2 3d 13 00 48 89 e3 48 83 e4 f0 ff d0 48 89 dc 89 44 24 38 48 83 c4 10 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}