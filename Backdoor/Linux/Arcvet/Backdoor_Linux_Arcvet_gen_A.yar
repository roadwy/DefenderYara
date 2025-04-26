
rule Backdoor_Linux_Arcvet_gen_A{
	meta:
		description = "Backdoor:Linux/Arcvet.gen!A,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {b6 b9 af b5 b6 af b0 b2 b8 af b0 b0 b1 } //2
		$a_01_1 = {d9 f7 e4 f3 81 d9 e2 e0 f5 81 } //2
		$a_01_2 = {e0 f4 e5 e8 f5 de ed ee e6 de f4 f2 e4 f3 de ec e4 f2 f2 e0 e6 e4 } //1
		$a_01_3 = {f2 f2 e9 e5 bb b0 88 a4 f2 88 a4 f2 88 a4 f2 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}