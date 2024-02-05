
rule Backdoor_Linux_Mirai_AU_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.AU!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 19 89 d0 01 d8 89 eb 30 18 89 d0 8b 19 01 d8 89 fb 30 18 89 d0 8b 19 01 d8 89 f3 30 18 89 d0 8b 19 42 01 d8 8a 1c 24 30 18 8b 41 04 25 ff ff 00 00 39 d0 7f ca } //01 00 
		$a_00_1 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //01 00 
		$a_00_2 = {68 6c 4c 6a 7a 74 71 5a } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Linux_Mirai_AU_MTB_2{
	meta:
		description = "Backdoor:Linux/Mirai.AU!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 8d 45 f3 6a 01 50 56 e8 90 02 05 83 c4 10 48 90 02 05 83 ec 0c 6a 04 e8 90 02 05 83 c4 10 0f be 45 f3 c1 e3 08 09 c3 81 fb 0a 0d 0a 0d 90 00 } //01 00 
		$a_03_1 = {8d 9d 60 ff ff ff 51 68 80 00 00 00 53 56 e8 90 02 05 ff 83 c4 10 85 c0 90 02 05 52 50 53 57 e8 90 02 05 83 c4 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}