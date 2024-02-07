
rule Worm_Win32_IRCbot_I{
	meta:
		description = "Worm:Win32/IRCbot.I,SIGNATURE_TYPE_PEHSTR,03 00 03 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 68 65 20 4f 6e 65 20 62 6f 74 73 70 72 65 61 64 2e 73 74 61 72 74 } //01 00  The One botspread.start
		$a_01_1 = {5b 50 32 50 20 53 70 72 65 61 64 5d 3a } //01 00  [P2P Spread]:
		$a_01_2 = {5b 45 6d 61 69 6c 20 53 70 72 65 61 64 5d 3a } //01 00  [Email Spread]:
		$a_01_3 = {5b 4c 41 4e 20 53 70 72 65 61 64 5d 3a } //01 00  [LAN Spread]:
		$a_01_4 = {5b 48 54 4d 4c 20 49 6e 66 65 63 74 6f 72 5d 3a } //01 00  [HTML Infector]:
		$a_01_5 = {5b 4d 53 4e 20 53 70 72 65 61 64 65 72 5d 3a 20 53 65 6e 74 20 74 6f 20 25 69 20 43 6f 6e 74 61 63 74 73 2e } //01 00  [MSN Spreader]: Sent to %i Contacts.
		$a_01_6 = {49 6e 66 65 63 74 65 64 20 44 72 69 76 65 20 25 73 } //01 00  Infected Drive %s
		$a_01_7 = {5b 53 53 59 4e 5d 3a 20 46 6c 6f 6f 64 69 6e 67 20 25 73 3a 25 73 20 66 6f 72 20 25 73 20 73 65 63 6f 6e 64 73 2e } //00 00  [SSYN]: Flooding %s:%s for %s seconds.
	condition:
		any of ($a_*)
 
}