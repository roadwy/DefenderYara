
rule Ransom_Win64_Crytox_AA_MTB{
	meta:
		description = "Ransom:Win64/Crytox.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 0f 38 dc 41 10 66 0f 38 dc 41 20 66 0f 38 dc 41 30 66 0f 38 dc 41 40 66 0f 38 dc 41 50 66 0f 38 dc 41 60 66 0f 38 dc 41 70 48 81 c1 80 00 00 00 66 0f 38 dc 01 66 0f 38 dc 41 10 48 83 c1 20 49 3b ca 72 ec 66 41 0f 38 dd 02 41 0f 11 01 49 83 c1 10 4c 3b c0 72 95 } //1
		$a_01_1 = {8a 84 31 08 12 00 00 f6 d0 8a 84 30 08 11 00 00 8a d0 d0 c2 32 c2 d0 c2 32 c2 d0 c2 32 c2 d0 c2 32 c2 34 63 88 84 31 08 10 00 00 fe c1 75 d1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}