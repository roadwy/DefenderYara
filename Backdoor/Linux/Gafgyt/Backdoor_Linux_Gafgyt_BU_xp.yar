
rule Backdoor_Linux_Gafgyt_BU_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BU!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {48 89 e5 48 81 ec 40 01 00 00 89 bd dc fe ff ff 48 8b 05 50 4d 11 00 48 85 c0 74 20 8b 85 dc fe ff ff 48 98 48 c1 e0 02 48 89 c2 48 8b 05 35 4d 11 00 48 8d 04 02 8b 00 85 c0 } //1
		$a_00_1 = {8b 4d fc 8b 45 fc 83 e8 03 48 98 8b 14 85 20 1d 51 00 8b 45 fc 83 e8 02 48 98 8b 04 85 20 1d 51 00 31 c2 8b 45 fc 31 d0 89 c2 81 f2 b9 79 37 9e 48 63 c1 89 14 85 20 1d 51 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}