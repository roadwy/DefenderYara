
rule Backdoor_Win32_IRCbot_BF{
	meta:
		description = "Backdoor:Win32/IRCbot.BF,SIGNATURE_TYPE_PEHSTR,2c 00 2c 00 0b 00 00 "
		
	strings :
		$a_01_0 = {2f 77 33 32 73 65 6e 64 2e 64 6c 6c } //10 /w32send.dll
		$a_01_1 = {2f 6d 65 73 73 70 61 73 73 2e 65 78 65 } //10 /messpass.exe
		$a_01_2 = {50 4f 50 33 20 50 61 73 73 77 6f 72 64 } //10 POP3 Password
		$a_01_3 = {75 73 65 72 69 6e 69 74 2e 65 78 65 2c 73 79 73 65 6d 33 32 2e 65 78 65 } //10 userinit.exe,sysem32.exe
		$a_01_4 = {67 65 74 69 63 71 } //1 geticq
		$a_01_5 = {50 52 49 56 4d 53 47 } //1 PRIVMSG
		$a_01_6 = {78 62 61 73 68 62 6f 74 } //1 xbashbot
		$a_01_7 = {6b 33 79 6c 6f 67 65 72 } //1 k3yloger
		$a_01_8 = {78 73 70 65 63 69 61 6c 64 6c } //1 xspecialdl
		$a_01_9 = {67 69 76 65 70 61 73 73 74 6f } //1 givepassto
		$a_01_10 = {64 30 77 6e 6c 6f 61 64 69 6e 67 } //1 d0wnloading
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=44
 
}