
rule Backdoor_Win32_IRCbot_gen_S{
	meta:
		description = "Backdoor:Win32/IRCbot.gen!S,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 61 75 74 6f 72 75 6e 5d } //01 00  [autorun]
		$a_01_1 = {5b 2e 53 68 65 6c 6c 43 6c 61 73 73 49 6e 66 6f 5d } //01 00  [.ShellClassInfo]
		$a_01_2 = {77 6f 72 6d 72 69 64 65 2e 74 66 74 70 64 } //01 00  wormride.tftpd
		$a_01_3 = {4a 4f 49 4e 20 25 73 } //01 00  JOIN %s
		$a_01_4 = {53 4d 42 72 } //00 00  SMBr
	condition:
		any of ($a_*)
 
}