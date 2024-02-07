
rule Backdoor_Win32_IRCbot_gen_B{
	meta:
		description = "Backdoor:Win32/IRCbot.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1c 00 0a 00 00 05 00 "
		
	strings :
		$a_01_0 = {64 69 72 78 39 2e 65 78 65 } //05 00  dirx9.exe
		$a_01_1 = {57 69 6e 6a 61 76 61 20 78 6d 6c } //05 00  Winjava xml
		$a_00_2 = {4a 4f 49 4e } //05 00  JOIN
		$a_00_3 = {4e 49 43 4b } //05 00  NICK
		$a_00_4 = {50 52 49 56 4d 53 47 } //01 00  PRIVMSG
		$a_01_5 = {74 68 72 65 61 64 73 } //01 00  threads
		$a_01_6 = {6b 69 6c 6c 74 68 72 65 61 64 } //01 00  killthread
		$a_01_7 = {65 78 65 63 75 74 65 } //01 00  execute
		$a_01_8 = {6c 69 73 74 70 72 6f 63 65 73 73 65 73 } //01 00  listprocesses
		$a_01_9 = {6b 69 6c 6c 70 72 6f 63 65 73 73 } //00 00  killprocess
	condition:
		any of ($a_*)
 
}