
rule Backdoor_BAT_Sisbot_A{
	meta:
		description = "Backdoor:BAT/Sisbot.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {21 00 64 00 64 00 6f 00 73 00 } //01 00  !ddos
		$a_01_1 = {21 00 73 00 74 00 6f 00 70 00 64 00 64 00 6f 00 73 00 } //01 00  !stopddos
		$a_01_2 = {21 00 69 00 72 00 63 00 } //01 00  !irc
		$a_01_3 = {21 00 73 00 74 00 6f 00 70 00 69 00 72 00 63 00 } //01 00  !stopirc
		$a_01_4 = {21 00 6d 00 69 00 72 00 63 00 } //01 00  !mirc
		$a_01_5 = {53 00 68 00 69 00 74 00 5f 00 49 00 52 00 43 00 5f 00 53 00 74 00 6f 00 72 00 6d 00 } //01 00  Shit_IRC_Storm
		$a_01_6 = {21 00 79 00 6f 00 75 00 74 00 75 00 62 00 65 00 } //00 00  !youtube
	condition:
		any of ($a_*)
 
}