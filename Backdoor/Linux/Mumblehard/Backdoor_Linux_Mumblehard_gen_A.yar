
rule Backdoor_Linux_Mumblehard_gen_A{
	meta:
		description = "Backdoor:Linux/Mumblehard.gen!A,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 5f 39 d3 75 13 81 fa ?? ?? 00 00 75 02 31 d2 81 c2 ?? 00 00 00 31 db 43 ac 30 d8 aa 43 e2 e2 } //1
		$a_03_1 = {89 f7 39 d3 75 13 81 fa ?? ?? 00 00 75 02 31 d2 81 c2 ?? 00 00 00 31 db 43 ac 30 d8 aa 43 e2 e2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}