
rule Backdoor_Linux_Tsunami_L_MTB{
	meta:
		description = "Backdoor:Linux/Tsunami.L!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {01 1e 4b a0 09 00 e3 61 dc 71 1e 51 10 61 18 21 0f 89 e3 61 dc 71 1f 51 13 62 01 72 e3 61 } //01 00 
		$a_00_1 = {04 40 03 99 e0 21 27 bd ff c0 af bf 00 38 af be 00 34 af b0 00 30 03 a0 f0 21 af bc 00 10 af c4 00 40 af c5 00 44 8f c2 00 40 00 } //01 00 
		$a_00_2 = {10 00 dc 8f 21 20 40 00 c4 4e 02 3c 4f ec 42 34 18 00 82 00 10 10 00 00 c3 18 02 00 c3 17 04 00 23 18 62 00 34 04 c3 } //00 00 
	condition:
		any of ($a_*)
 
}