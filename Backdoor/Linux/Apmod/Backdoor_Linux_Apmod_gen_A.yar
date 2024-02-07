
rule Backdoor_Linux_Apmod_gen_A{
	meta:
		description = "Backdoor:Linux/Apmod.gen!A,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 41 4e 5f 55 53 45 52 41 47 45 4e 54 } //01 00  BAN_USERAGENT
		$a_01_1 = {43 48 45 43 4b 5f 42 4f 54 5f 55 53 45 52 41 47 45 4e 54 } //01 00  CHECK_BOT_USERAGENT
		$a_01_2 = {43 48 45 43 4b 5f 52 41 57 5f 43 4f 4f 4b 49 45 } //01 00  CHECK_RAW_COOKIE
		$a_01_3 = {53 45 5f 52 45 46 45 52 45 52 } //01 00  SE_REFERER
		$a_01_4 = {54 41 47 53 5f 46 4f 52 5f 49 4e 4a 45 43 54 } //00 00  TAGS_FOR_INJECT
	condition:
		any of ($a_*)
 
}