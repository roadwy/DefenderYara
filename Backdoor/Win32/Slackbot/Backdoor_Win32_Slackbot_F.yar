
rule Backdoor_Win32_Slackbot_F{
	meta:
		description = "Backdoor:Win32/Slackbot.F,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {4e 49 43 4b 20 25 73 } //01 00  NICK %s
		$a_00_1 = {63 68 61 6e 67 65 64 25 73 25 73 25 73 54 6f 25 73 25 73 } //01 00  changed%s%s%sTo%s%s
		$a_00_2 = {63 6f 70 79 6d 65 } //01 00  copyme
		$a_00_3 = {3f 4b 69 6c 6c 65 64 3d } //01 00  ?Killed=
		$a_00_4 = {21 53 65 6e 64 6b 65 79 4c 6f 67 54 6f 53 65 72 76 65 72 } //01 00  !SendkeyLogToServer
		$a_02_5 = {2e 00 65 00 78 00 65 00 74 00 6d 00 70 00 90 02 04 2e 00 76 00 62 00 73 00 90 00 } //00 00 
		$a_00_6 = {5d 04 00 } //00 53 
	condition:
		any of ($a_*)
 
}