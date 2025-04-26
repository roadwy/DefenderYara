
rule Backdoor_Linux_Gafgyt_CP_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.CP!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {d8 af be 00 20 03 a0 f0 21 24 03 49 5e 00 00 10 21 af c3 } //1
		$a_00_1 = {fe 8f 83 80 18 00 02 20 80 24 62 9b d0 00 } //1
		$a_00_2 = {24 42 9b d0 ac 43 00 08 24 02 00 03 af c2 00 08 } //1
		$a_00_3 = {9b d0 ac 43 00 04 8f c3 00 18 3c 02 3c 6e 34 42 f3 72 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}