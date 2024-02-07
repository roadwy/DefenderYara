
rule Backdoor_Win32_IRCbot_OY{
	meta:
		description = "Backdoor:Win32/IRCbot.OY,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {fc b9 39 00 00 00 f3 a4 8b 45 f4 89 04 24 e8 } //01 00 
		$a_01_1 = {25 71 25 62 25 62 2e 63 76 63 } //01 00  %q%b%b.cvc
		$a_01_2 = {54 63 70 71 67 6d 6c 3a } //01 00  Tcpqgml:
		$a_01_3 = {0d 0a 4e 50 47 54 4b 51 45 20 25 71 } //01 00 
		$a_01_4 = {53 51 43 50 20 25 71 20 22 } //01 00  SQCP %q "
		$a_01_5 = {25 64 2e 25 64 2e 25 64 2e 25 64 00 00 00 00 00 30 31 32 33 34 } //01 00 
		$a_01_6 = {25 73 5b 25 73 5d 00 5f 00 00 00 00 53 51 43 50 } //00 00 
	condition:
		any of ($a_*)
 
}