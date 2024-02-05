
rule Backdoor_Linux_Tsunami_K_xp{
	meta:
		description = "Backdoor:Linux/Tsunami.K!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 89 e5 48 81 ec f0 00 00 00 89 bd 2c ff ff ff 48 89 95 60 ff ff ff 48 89 8d 68 ff ff ff 4c 89 85 70 ff ff ff 4c 89 8d 78 ff ff ff 0f b6 c0 48 89 85 18 ff ff ff 48 8b 95 18 ff ff ff 48 8d 04 95 00 00 00 00 48 c7 85 18 ff ff ff 47 05 40 00 48 29 85 18 ff ff ff 48 8d 45 ff 48 8b bd 18 ff ff ff } //01 00 
		$a_03_1 = {55 48 89 e5 48 83 ec 30 48 89 7d d8 0f b6 05 c5 bf 10 00 3c 01 75 25 8b 3d 07 e7 10 00 48 8b 55 d8 be f9 9d 40 00 b8 00 00 00 00 e8 90 01 04 c7 45 d4 01 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}