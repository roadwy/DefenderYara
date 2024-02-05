
rule Backdoor_Linux_Gafgyt_V_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.V!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 20 a0 e3 24 30 4b e5 23 20 4b e5 90 01 01 0d a0 e3 90 01 01 00 80 e2 90 01 02 00 eb 00 30 a0 e1 22 30 4b e5 43 34 a0 e1 21 30 4b e5 90 01 02 9f e5 90 01 02 00 eb 00 30 a0 e1 20 30 0b e5 24 30 4b e2 14 00 1b e5 03 10 a0 e1 10 20 a0 e3 90 01 02 00 eb 00 30 a0 e1 10 30 0b e5 10 30 1b e5 01 00 73 e3 02 00 00 1a 14 00 1b e5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}