
rule Backdoor_Linux_Mirai_BS_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BS!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {a0 03 2a 70 00 16 82 70 02 00 74 c2 08 73 14 14 1f 30 40 22 44 00 15 23 82 00 00 a5 00 1e 02 11 01 d8 } //1
		$a_00_1 = {00 34 10 1c 40 34 14 1c 80 34 18 1c c0 34 1c 1c 00 35 20 1c 40 35 24 1c 80 35 2f 0d 34 11 28 1c c0 35 08 77 42 0d 20 03 00 80 42 25 02 11 1b 0a } //1
		$a_00_2 = {c0 d0 1c 48 b3 41 c6 42 c7 0c 1c 00 34 10 1c 40 34 14 1c 80 34 18 1c c0 34 2c 1c 00 36 1c 1c } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}