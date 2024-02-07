
rule Backdoor_Win32_IRCbot_FZ{
	meta:
		description = "Backdoor:Win32/IRCbot.FZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 49 43 4b 20 00 00 00 55 53 45 52 20 00 } //01 00 
		$a_01_1 = {28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 47 6f 6f 67 6c 65 62 6f 74 2f } //01 00  (compatible; Googlebot/
		$a_01_2 = {3a 53 4c 4f 57 4c 4f 52 49 53 20 46 6c 6f 6f 64 20 41 63 74 69 76 61 74 65 64 21 } //01 00  :SLOWLORIS Flood Activated!
		$a_00_3 = {ff d3 33 d2 b9 34 00 00 00 f7 f1 8b c6 83 e0 07 46 3b f7 } //00 00 
	condition:
		any of ($a_*)
 
}