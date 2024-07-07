
rule Backdoor_BAT_IRCbot_L_bit{
	meta:
		description = "Backdoor:BAT/IRCbot.L!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 53 42 49 6e 66 65 63 74 69 6f 6e } //1 USBInfection
		$a_01_1 = {53 65 61 66 6b 6f 41 67 65 6e 74 2e 49 52 43 43 6c 69 6e 65 74 } //1 SeafkoAgent.IRCClinet
		$a_01_2 = {53 74 61 72 74 4b 65 79 4c 6f 67 67 65 72 } //1 StartKeyLogger
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}