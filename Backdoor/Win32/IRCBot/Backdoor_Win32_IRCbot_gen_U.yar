
rule Backdoor_Win32_IRCbot_gen_U{
	meta:
		description = "Backdoor:Win32/IRCbot.gen!U,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 0b 00 00 02 00 "
		
	strings :
		$a_03_0 = {69 c0 18 02 00 00 90 09 16 00 81 bd 90 01 02 ff ff 00 02 00 00 90 03 01 02 7d 0f 8d 90 00 } //02 00 
		$a_03_1 = {8a 00 32 81 90 01 04 8b 4d 08 03 4d fc 88 01 eb ce 90 00 } //02 00 
		$a_03_2 = {83 f8 62 74 90 01 01 8d 45 90 01 01 50 ff 15 90 01 03 3f 83 f8 02 75 90 00 } //01 00 
		$a_01_3 = {46 69 6c 65 20 64 6f 77 6e 6c 6f 61 64 3a 20 25 2e 31 66 4b 42 20 74 6f 3a 20 25 73 20 40 20 25 2e 31 66 4b 42 2f 73 65 63 2e } //01 00  File download: %.1fKB to: %s @ %.1fKB/sec.
		$a_01_4 = {25 73 20 46 6c 6f 6f 64 69 6e 67 20 25 73 3a 25 73 20 66 6f 72 20 25 73 20 73 65 63 6f 6e 64 73 } //01 00  %s Flooding %s:%s for %s seconds
		$a_01_5 = {5b 61 75 74 6f 72 75 6e 5d } //01 00  [autorun]
		$a_01_6 = {49 6e 66 65 63 74 65 64 20 64 72 69 76 65 3a 20 25 73 } //01 00  Infected drive: %s
		$a_01_7 = {44 6f 6e 65 20 77 69 74 68 20 66 6c 6f 6f 64 20 28 25 69 4b 42 2f 73 65 63 29 2e 30 35 } //01 00  Done with flood (%iKB/sec).05
		$a_01_8 = {25 73 20 44 6f 77 6e 6c 6f 61 64 69 6e 67 20 55 52 4c 3a 20 25 73 20 74 6f 3a 20 25 73 2e } //01 00  %s Downloading URL: %s to: %s.
		$a_01_9 = {25 73 5c 72 65 6d 6f 76 65 4d 65 25 69 25 69 25 69 25 69 2e 62 61 74 } //01 00  %s\removeMe%i%i%i%i.bat
		$a_01_10 = {50 69 6e 67 20 54 69 6d 65 6f 75 74 3f 20 28 25 64 2d 25 64 29 25 64 2f 25 64 } //00 00  Ping Timeout? (%d-%d)%d/%d
	condition:
		any of ($a_*)
 
}