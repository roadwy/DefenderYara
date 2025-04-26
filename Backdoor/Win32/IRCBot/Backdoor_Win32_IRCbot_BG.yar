
rule Backdoor_Win32_IRCbot_BG{
	meta:
		description = "Backdoor:Win32/IRCbot.BG,SIGNATURE_TYPE_PEHSTR,29 00 28 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 66 62 69 2e 67 6f 76 } //10 .fbi.gov
		$a_01_1 = {53 74 61 72 74 20 66 6c 6f 6f 64 69 6e 67 } //10 Start flooding
		$a_01_2 = {49 6e 74 65 72 6e 65 74 20 53 65 63 75 72 69 74 79 20 53 65 72 76 69 63 65 } //10 Internet Security Service
		$a_01_3 = {7b 32 38 41 42 43 35 43 30 2d 34 46 43 42 2d 31 31 43 46 2d 41 41 58 35 2d 38 31 43 58 31 43 36 33 35 36 31 32 7d } //10 {28ABC5C0-4FCB-11CF-AAX5-81CX1C635612}
		$a_01_4 = {69 72 63 2e 68 31 74 33 6d 2e 6f 72 67 } //1 irc.h1t3m.org
		$a_01_5 = {69 73 65 33 32 2e 65 78 65 } //1 ise32.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=40
 
}