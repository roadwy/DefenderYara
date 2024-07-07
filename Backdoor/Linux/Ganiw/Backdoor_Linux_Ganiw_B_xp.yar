
rule Backdoor_Linux_Ganiw_B_xp{
	meta:
		description = "Backdoor:Linux/Ganiw.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {55 89 e5 57 56 53 83 ec 2c 8b 45 0c 8b 55 18 8b 4d 1c 8b 5d 20 8b 75 24 88 45 e0 66 89 55 dc 88 4d d8 66 89 5d d4 89 f0 88 45 d0 8b 45 08 89 45 e4 8a 45 e0 83 f0 01 84 c0 } //1
		$a_00_1 = {55 89 e5 83 ec 08 e8 00 00 00 00 5a 81 c2 39 95 0e 00 b8 64 7d 0d 0a 08 85 c0 74 15 52 6a 00 68 e4 2b 13 08 68 40 c7 11 08 e8 83 fb 05 00 83 c4 10 a1 48 10 13 08 85 c0 74 16 b8 00 00 00 00 85 c0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}