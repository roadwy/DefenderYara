
rule Ransom_Linux_Lockton_A_MTB{
	meta:
		description = "Ransom:Linux/Lockton.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 36 52 61 6e 73 6f 6d 77 61 72 65 57 69 6e 64 6f 77 } //1 16RansomwareWindow
		$a_01_1 = {48 8d 15 bb 49 00 00 48 89 d1 ba 20 03 00 00 be dc 05 00 00 48 89 c7 e8 c3 b9 ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}