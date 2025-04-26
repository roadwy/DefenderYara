
rule Backdoor_Linux_Gafgyt_CE_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.CE!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 48 c7 c7 30 85 40 00 48 c7 c1 e8 00 40 00 49 c7 c0 88 7a 41 00 } //1
		$a_00_1 = {48 8b 45 98 8b 50 0c 48 8b 45 a8 89 50 0c 48 8b 45 a0 8b 10 48 8b 45 a8 66 89 50 10 48 8b 7d a8 } //1
		$a_00_2 = {48 89 c6 48 8b 84 c5 10 fe ff ff 48 89 c2 48 8b 85 60 ff ff ff 8b 00 89 c1 83 e1 3f b8 01 00 00 00 48 d3 e0 48 09 d0 48 89 84 f5 10 fe ff ff 48 8b 85 60 ff ff ff 8b 00 3b 85 78 ff ff ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}