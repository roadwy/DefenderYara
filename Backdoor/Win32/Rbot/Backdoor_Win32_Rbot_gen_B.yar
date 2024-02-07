
rule Backdoor_Win32_Rbot_gen_B{
	meta:
		description = "Backdoor:Win32/Rbot.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,17 00 14 00 0b 00 00 05 00 "
		
	strings :
		$a_00_0 = {50 43 20 4e 45 54 57 4f 52 4b 20 50 52 4f 47 52 41 4d 20 31 2e 30 } //03 00  PC NETWORK PROGRAM 1.0
		$a_01_1 = {66 75 6b 6f 66 66 } //03 00  fukoff
		$a_01_2 = {72 65 62 6f 6f 74 } //03 00  reboot
		$a_01_3 = {6e 69 63 6b } //03 00  nick
		$a_01_4 = {6a 6f 69 6e } //01 00  join
		$a_01_5 = {24 2f 20 69 70 63 76 } //01 00  $/ ipcv
		$a_01_6 = {41 64 6d 69 6e 24 5c 73 79 73 } //01 00  Admin$\sys
		$a_01_7 = {63 24 5c 77 69 6e 6e 74 } //01 00  c$\winnt
		$a_01_8 = {28 6e 6f 20 70 61 73 73 77 6f 72 64 29 } //01 00  (no password)
		$a_01_9 = {45 78 70 6c 6f 69 74 69 6e 67 20 49 50 3a 20 } //01 00  Exploiting IP: 
		$a_01_10 = {55 73 65 72 3a 20 28 25 73 29 20 50 5c } //00 00  User: (%s) P\
	condition:
		any of ($a_*)
 
}