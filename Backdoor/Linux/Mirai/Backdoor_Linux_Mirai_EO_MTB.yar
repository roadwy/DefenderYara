
rule Backdoor_Linux_Mirai_EO_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.EO!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {55 69 04 3e 55 60 84 3e 7c 00 4a 14 54 ea 04 3e 89 63 00 09 54 e9 84 3e 7d 28 4a 14 7c 00 52 14 7d 29 5a 14 7c 00 2a 14 7c 09 02 14 54 09 84 3f 41 82 00 14 } //01 00 
		$a_00_1 = {81 23 00 00 7c 0a 48 ae 7c c0 02 78 7c 0a 49 ae 81 63 00 00 7c 0a 58 ae 7c e0 02 78 7c 0a 59 ae 81 23 00 00 7c 0a 48 ae 7d 00 02 78 7c 0a 49 ae 81 63 00 00 7c 0a 58 ae 7c a0 02 78 7c 0a 59 ae 39 4a 00 01 a0 03 00 04 7f 80 50 00 41 9d ff b4 } //00 00 
	condition:
		any of ($a_*)
 
}