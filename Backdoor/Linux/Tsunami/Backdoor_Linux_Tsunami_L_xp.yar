
rule Backdoor_Linux_Tsunami_L_xp{
	meta:
		description = "Backdoor:Linux/Tsunami.L!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 0f b6 00 0f b6 c0 89 04 24 e8 ?? ?? ?? ?? 89 c3 8b 45 0c 0f b6 00 0f b6 c0 89 04 24 e8 ?? ?? ?? ?? 39 c3 75 18 8b 45 0c 40 8b 55 08 42 89 44 24 04 89 14 24 } //1
		$a_00_1 = {89 c8 f7 d0 48 39 c2 73 0d 8b 45 e4 03 45 0c 0f b6 00 3c 21 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}