
rule Backdoor_Linux_Mirai_BO_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BO!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {48 e7 3c 00 42 80 10 2f 00 17 22 00 e7 89 d0 80 92 80 22 41 d3 fc 80 00 fe 04 20 39 80 00 fb 32 4a 69 00 04 67 38 1a 00 28 00 e0 8c 26 00 42 43 48 43 24 00 72 18 } //1
		$a_00_1 = {20 41 d1 d1 bb 10 20 41 d1 d1 b9 10 20 41 d1 d1 b7 10 20 41 d1 d1 b5 10 52 81 42 80 30 29 00 04 b2 80 } //1
		$a_00_2 = {10 19 14 00 49 c2 16 02 49 c3 0c 03 00 20 67 f0 0c 03 00 09 67 ea 0c 03 00 0a 67 e4 0c 00 00 2d 67 00 00 bc 0c 00 00 2b 67 00 00 a0 20 3c 7f ff ff ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}