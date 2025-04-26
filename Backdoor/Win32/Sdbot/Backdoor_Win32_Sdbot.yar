
rule Backdoor_Win32_Sdbot{
	meta:
		description = "Backdoor:Win32/Sdbot,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0e 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 53 65 72 76 69 63 65 73 } //1 Software\Microsoft\Windows\CurrentVersion\RunServices
		$a_00_1 = {49 63 6d 70 53 65 6e 64 45 63 68 6f } //2 IcmpSendEcho
		$a_00_2 = {50 6f 72 74 66 75 63 6b 20 63 6f 6d 70 6c 65 74 65 64 } //2 Portfuck completed
		$a_00_3 = {53 59 4e 20 66 6c 6f 6f 64 } //2 SYN flood
		$a_00_4 = {73 64 62 6f 74 20 76 } //2 sdbot v
		$a_00_5 = {73 64 62 6f 74 20 30 2e 35 62 } //2 sdbot 0.5b
		$a_00_6 = {73 64 62 6f 74 2e 6e } //2 sdbot.n
		$a_00_7 = {62 6f 74 20 73 74 61 72 74 65 64 2e } //2 bot started.
		$a_00_8 = {25 73 5c 72 2e 62 61 74 } //1 %s\r.bat
		$a_00_9 = {73 70 79 20 63 72 65 61 74 65 64 20 6f 6e } //2 spy created on
		$a_00_10 = {63 6c 6f 6e 65 20 63 72 65 61 74 65 64 20 6f 6e 20 25 73 3a 25 64 2c 20 69 6e 20 63 68 61 6e 6e 65 6c 20 25 73 2e } //1 clone created on %s:%d, in channel %s.
		$a_00_11 = {63 6f 6e 6e 65 63 74 69 6f 6e 20 74 79 70 65 3a 20 25 73 20 28 25 73 29 2e 20 6c 6f 63 61 6c 20 49 50 20 61 64 64 72 65 73 73 3a 20 25 64 2e 25 64 2e 25 64 2e 25 64 2e 20 63 6f 6e 6e 65 63 74 65 64 20 66 72 6f 6d 3a 20 25 73 } //1 connection type: %s (%s). local IP address: %d.%d.%d.%d. connected from: %s
		$a_80_12 = {4d 63 41 66 65 65 20 53 74 69 6e 67 65 72 } //McAfee Stinger  -10
		$a_00_13 = {4d 00 63 00 41 00 66 00 65 00 65 00 20 00 49 00 6e 00 63 00 2e 00 20 00 53 00 74 00 69 00 6e 00 67 00 65 00 72 00 } //-10 McAfee Inc. Stinger
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2+(#a_00_7  & 1)*2+(#a_00_8  & 1)*1+(#a_00_9  & 1)*2+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_80_12  & 1)*-10+(#a_00_13  & 1)*-10) >=8
 
}