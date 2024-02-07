
rule Worm_Win32_Pushbot_gen_B{
	meta:
		description = "Worm:Win32/Pushbot.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 14 00 0c 00 00 01 00 "
		
	strings :
		$a_00_0 = {56 4e 43 20 53 63 61 6e 6e 69 6e 67 20 42 6f 74 } //01 00  VNC Scanning Bot
		$a_00_1 = {52 46 42 20 30 30 33 2e 30 30 38 } //01 00  RFB 003.008
		$a_00_2 = {5b 4d 41 49 4e 5d } //01 00  [MAIN]
		$a_00_3 = {52 58 42 6f 74 } //01 00  RXBot
		$a_00_4 = {5b 53 43 41 4e 5d } //01 00  [SCAN]
		$a_00_5 = {5b 46 54 50 5d } //01 00  [FTP]
		$a_00_6 = {73 63 61 6e 2e 73 74 6f 70 } //01 00  scan.stop
		$a_00_7 = {4e 5a 4d 2f 53 54 } //01 00  NZM/ST
		$a_00_8 = {73 63 61 6e 61 6c 6c } //01 00  scanall
		$a_00_9 = {59 61 42 6f 74 } //14 00  YaBot
		$a_03_10 = {59 85 c0 59 74 1b 81 ec 28 01 00 00 8d 75 90 01 01 6a 4a 59 8b fc f3 a5 e8 90 01 04 81 c4 28 01 00 00 83 c3 08 8b c3 83 3b 00 75 90 01 01 b9 00 14 00 00 90 00 } //0f 00 
		$a_03_11 = {6a 00 6a 04 8d 45 90 01 01 50 6a 07 ff 75 08 ff 55 90 01 01 85 c0 75 0a 83 7d 90 01 01 00 74 04 b0 01 eb 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}