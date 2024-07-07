
rule Backdoor_Linux_Enemybot_A{
	meta:
		description = "Backdoor:Linux/Enemybot.A,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {45 4e 45 4d 45 59 42 4f 54 } //1 ENEMEYBOT
		$a_00_1 = {65 6e 65 6d 79 } //1 enemy
		$a_00_2 = {44 61 74 61 20 50 61 79 6c 6f 61 64 } //1 Data Payload
		$a_00_3 = {4b 45 4b 53 45 43 } //1 KEKSEC
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}