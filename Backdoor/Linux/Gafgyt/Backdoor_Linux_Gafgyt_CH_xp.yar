
rule Backdoor_Linux_Gafgyt_CH_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.CH!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 4d fc 8b 45 fc 83 e8 03 48 98 8b 14 85 40 d6 50 00 8b 45 fc 83 e8 02 48 98 8b 04 85 40 d6 50 00 31 c2 8b 45 fc 31 d0 89 c2 81 f2 b9 79 37 9e 48 63 c1 89 14 85 40 d6 50 00 ff 45 fc } //1
		$a_03_1 = {48 89 e5 48 83 ec 20 89 7d ec 8b 3d 3f 36 11 00 e8 ?? ?? ?? ?? 23 45 ec 89 45 fc e8 ?? ?? ?? ?? 89 c2 8b 45 ec f7 d0 21 d0 33 45 fc } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}