
rule Backdoor_Win32_IRCbot_gen_D{
	meta:
		description = "Backdoor:Win32/IRCbot.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 08 00 00 "
		
	strings :
		$a_00_0 = {53 70 72 65 61 64 69 6e 67 20 77 69 74 68 20 73 74 61 72 74 20 61 64 64 72 65 73 73 20 5b 25 73 5d } //1 Spreading with start address [%s]
		$a_00_1 = {53 70 72 65 61 64 20 72 6f 75 74 69 6e 65 20 73 74 6f 70 70 65 64 } //1 Spread routine stopped
		$a_00_2 = {2e 6b 6c 20 3c 61 70 70 6c 69 63 61 74 69 6f 6e 7c 73 65 63 75 72 69 74 79 7c 73 79 73 74 65 6d 3e } //1 .kl <application|security|system>
		$a_00_3 = {2e 6c 6f 67 69 6e 20 3c 68 61 73 68 3e } //1 .login <hash>
		$a_00_4 = {2e 75 70 64 61 74 65 20 3c 75 6e 69 78 7c 77 69 6e 33 32 3e 20 3c 75 72 6c 3e } //1 .update <unix|win32> <url>
		$a_00_5 = {41 74 74 65 6d 70 74 69 6e 67 20 72 65 6d 6f 74 65 20 65 78 65 63 75 74 69 6f 6e 2e 2e 2e } //1 Attempting remote execution...
		$a_01_6 = {73 75 70 61 73 73 } //1 supass
		$a_00_7 = {3a 52 65 73 74 61 72 74 69 6e 67 20 62 6f 74 2e } //1 :Restarting bot.
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1) >=6
 
}