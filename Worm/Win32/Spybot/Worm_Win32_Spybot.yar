
rule Worm_Win32_Spybot{
	meta:
		description = "Worm:Win32/Spybot,SIGNATURE_TYPE_PEHSTR,08 00 06 00 0c 00 00 04 00 "
		
	strings :
		$a_01_0 = {53 65 72 76 65 72 3a 20 53 70 79 42 6f 74 } //01 00  Server: SpyBot
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4b 41 5a 41 41 5c 4c 6f 63 61 6c 43 6f 6e 74 65 6e 74 } //01 00  SOFTWARE\KAZAA\LocalContent
		$a_01_2 = {50 52 49 56 4d 53 47 } //01 00  PRIVMSG
		$a_01_3 = {52 65 67 69 73 74 65 72 53 65 72 76 69 63 65 50 72 6f 63 65 73 73 } //01 00  RegisterServiceProcess
		$a_01_4 = {5c 63 6d 64 2e 65 78 65 } //01 00  \cmd.exe
		$a_01_5 = {4b 65 79 6c 6f 67 67 65 72 20 53 74 61 72 74 65 64 } //02 00  Keylogger Started
		$a_01_6 = {53 79 6e 46 6c 6f 6f 64 69 6e 67 3a } //02 00  SynFlooding:
		$a_01_7 = {57 4e 65 74 45 6e 75 6d 43 61 63 68 65 64 50 61 73 73 77 6f 72 64 73 } //02 00  WNetEnumCachedPasswords
		$a_01_8 = {73 70 79 62 6f 74 31 2e 32 63 } //02 00  spybot1.2c
		$a_01_9 = {73 74 61 72 74 6b 65 79 6c 6f 67 67 65 72 } //02 00  startkeylogger
		$a_01_10 = {41 56 50 5f 43 72 61 63 6b 2e 65 78 65 } //02 00  AVP_Crack.exe
		$a_01_11 = {7a 6f 6e 65 61 6c 6c 61 72 6d 5f 70 72 6f 5f 63 72 61 63 6b 2e 65 78 65 } //00 00  zoneallarm_pro_crack.exe
	condition:
		any of ($a_*)
 
}