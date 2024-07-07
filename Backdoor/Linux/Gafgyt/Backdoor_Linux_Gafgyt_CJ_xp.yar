
rule Backdoor_Linux_Gafgyt_CJ_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.CJ!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 4d fc 8b 45 fc 83 e8 03 48 98 8b 14 85 60 19 51 00 8b 45 fc 83 e8 02 48 98 8b 04 85 60 19 51 00 31 c2 8b 45 fc 31 d0 89 c2 81 f2 b9 79 37 9e 48 63 c1 89 14 85 60 19 51 00 ff 45 fc } //1
		$a_00_1 = {55 48 89 e5 89 7d ec 8b 45 ec 89 05 90 17 11 00 8b 45 ec 2d 47 86 c8 61 89 05 86 17 11 00 8b 45 ec 05 72 f3 6e 3c } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}