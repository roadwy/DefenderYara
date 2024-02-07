
rule Backdoor_Win32_IRCbot_gen_E{
	meta:
		description = "Backdoor:Win32/IRCbot.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 54 54 50 20 46 6c 6f 6f 64 65 72 3a 20 63 6f 75 6c 64 6e 6f 74 } //01 00  HTTP Flooder: couldnot
		$a_01_1 = {49 43 4d 50 20 46 6c 6f 6f 64 65 72 20 65 72 72 6f 72 3a } //01 00  ICMP Flooder error:
		$a_01_2 = {55 44 50 20 46 6c 6f 6f 64 20 74 65 72 6d 69 6e 61 74 65 64 } //01 00  UDP Flood terminated
		$a_00_3 = {55 6e 61 62 6c 65 20 74 6f 20 6b 69 6c 6c 20 70 72 6f 63 65 73 73 20 77 69 74 68 20 50 49 44 20 25 64 } //01 00  Unable to kill process with PID %d
		$a_00_4 = {75 5f 74 68 72 65 61 64 20 72 65 77 72 69 74 65 64 20 74 6f 20 25 64 } //01 00  u_thread rewrited to %d
		$a_00_5 = {59 6f 75 20 61 72 65 20 61 6c 72 65 61 64 79 20 6c 6f 67 67 69 6e 65 64 20 61 73 20 61 64 6d 69 6e } //01 00  You are already loggined as admin
		$a_01_6 = {44 43 43 20 53 68 65 6c 6c 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 65 73 74 61 62 6c 69 73 68 65 64 20 77 69 74 68 20 25 73 2e 2e 2e } //00 00  DCC Shell connection established with %s...
	condition:
		any of ($a_*)
 
}