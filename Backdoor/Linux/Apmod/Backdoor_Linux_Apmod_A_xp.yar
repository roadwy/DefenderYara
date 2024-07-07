
rule Backdoor_Linux_Apmod_A_xp{
	meta:
		description = "Backdoor:Linux/Apmod.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {41 89 c0 41 89 c9 41 89 ca 41 c1 e8 0b 41 c1 e2 04 41 c1 e9 05 41 83 e0 03 45 31 d1 46 8b 04 86 41 01 c9 41 01 c0 05 47 86 c8 61 45 31 c8 44 29 c2 49 89 c0 41 83 e0 03 41 89 d1 41 89 d2 46 8b 04 86 41 c1 e9 05 41 c1 e2 04 45 31 d1 41 01 d1 41 01 c0 45 31 c8 44 29 c1 85 c0 } //1
		$a_00_1 = {31 c0 48 85 ff 74 5c 31 f6 45 31 c0 31 d2 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}