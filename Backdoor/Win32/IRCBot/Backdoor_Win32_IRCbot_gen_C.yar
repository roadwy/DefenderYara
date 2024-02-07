
rule Backdoor_Win32_IRCbot_gen_C{
	meta:
		description = "Backdoor:Win32/IRCbot.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 59 53 20 45 72 72 6f 72 3a 20 25 64 } //01 00  NYS Error: %d
		$a_01_1 = {4e 59 53 20 46 6c 30 30 64 } //01 00  NYS Fl00d
		$a_01_2 = {6e 65 74 20 73 68 61 72 65 20 43 24 20 2f 64 65 6c 65 74 65 20 2f 79 } //01 00  net share C$ /delete /y
		$a_01_3 = {67 6e 69 70 20 28 25 73 29 } //01 00  gnip (%s)
		$a_01_4 = {72 63 70 74 20 74 6f 3a 20 3c 25 73 3e } //01 00  rcpt to: <%s>
		$a_01_5 = {4e 49 43 4b 3a 20 25 73 } //01 00  NICK: %s
		$a_01_6 = {28 4e 54 53 20 74 61 74 73 29 3a } //00 00  (NTS tats):
	condition:
		any of ($a_*)
 
}