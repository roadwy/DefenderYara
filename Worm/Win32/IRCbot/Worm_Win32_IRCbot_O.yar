
rule Worm_Win32_IRCbot_O{
	meta:
		description = "Worm:Win32/IRCbot.O,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 5f 41 75 74 6f 52 75 6e 2e 65 78 65 00 } //01 00 
		$a_01_1 = {56 4e 43 25 64 2e 25 64 20 25 73 3a 20 25 73 3a 25 64 20 2d 20 5b 41 75 74 68 42 79 70 61 73 73 5d } //01 00  VNC%d.%d %s: %s:%d - [AuthBypass]
		$a_01_2 = {4c 6f 6f 6b 20 61 74 20 74 68 69 73 20 70 69 63 74 75 72 65 20 25 73 } //01 00  Look at this picture %s
		$a_01_3 = {63 6d 64 20 2f 63 20 6e 65 74 20 73 74 6f 70 20 53 68 61 72 65 64 41 63 63 65 73 73 20 26 65 63 68 6f 20 6f 70 65 6e 20 25 73 20 25 64 20 3e 3e 20 69 6a 20 26 65 63 68 6f 20 75 73 65 72 20 25 73 20 25 73 20 3e 3e 20 69 6a 20 26 65 63 68 6f } //01 00  cmd /c net stop SharedAccess &echo open %s %d >> ij &echo user %s %s >> ij &echo
		$a_01_4 = {00 63 66 74 70 2e 67 65 74 00 } //01 00 
		$a_01_5 = {53 63 61 6e 6e 65 72 20 61 6c 72 65 61 64 79 20 72 75 6e 6e 69 6e 67 } //00 00  Scanner already running
	condition:
		any of ($a_*)
 
}