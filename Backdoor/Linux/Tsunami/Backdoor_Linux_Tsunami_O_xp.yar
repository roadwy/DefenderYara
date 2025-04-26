
rule Backdoor_Linux_Tsunami_O_xp{
	meta:
		description = "Backdoor:Linux/Tsunami.O!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 45 54 53 50 4f 4f 46 53 } //1 GETSPOOFS
		$a_01_1 = {48 54 54 50 46 4c 4f 4f 44 } //1 HTTPFLOOD
		$a_01_2 = {25 73 20 3a 52 65 6d 6f 76 65 64 20 61 6c 6c 20 73 70 6f 6f 66 73 } //1 %s :Removed all spoofs
		$a_01_3 = {50 52 49 56 4d 53 47 20 25 73 20 3a 53 70 6f 6f 66 73 } //1 PRIVMSG %s :Spoofs
		$a_01_4 = {42 65 73 6c 69 73 74 42 6f 74 } //1 BeslistBot
		$a_01_5 = {6d 78 62 6f 74 2f 31 2e 30 } //1 mxbot/1.0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}