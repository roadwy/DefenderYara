
rule Backdoor_Win32_IRCbot_AQ{
	meta:
		description = "Backdoor:Win32/IRCbot.AQ,SIGNATURE_TYPE_PEHSTR,49 00 49 00 10 00 00 "
		
	strings :
		$a_01_0 = {25 64 2e 25 64 2e 25 64 2e 25 64 } //10 %d.%d.%d.%d
		$a_01_1 = {50 52 49 56 4d 53 47 20 25 73 } //10 PRIVMSG %s
		$a_01_2 = {4a 4f 49 4e 20 25 73 20 25 73 } //10 JOIN %s %s
		$a_01_3 = {55 53 45 52 48 4f 53 54 20 25 73 } //10 USERHOST %s
		$a_01_4 = {46 74 70 4f 70 65 6e 46 69 6c 65 41 } //10 FtpOpenFileA
		$a_01_5 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //10 InternetReadFile
		$a_01_6 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //10 CreateToolhelp32Snapshot
		$a_01_7 = {62 6f 74 5f 75 70 64 61 74 65 } //1 bot_update
		$a_01_8 = {74 68 72 65 61 64 5f 6b 69 6c 6c } //1 thread_kill
		$a_01_9 = {66 69 6c 65 5f 64 65 6c 65 74 65 } //1 file_delete
		$a_01_10 = {74 68 72 65 61 64 73 5f 6c 69 73 74 } //1 threads_list
		$a_01_11 = {70 72 6f 63 65 73 73 5f 6b 69 6c 6c } //1 process_kill
		$a_01_12 = {66 69 6c 65 5f 64 6f 77 6e 6c 6f 61 64 } //1 file_download
		$a_01_13 = {62 6f 74 5f 72 65 63 6f 6e 6e 65 63 74 } //1 bot_reconnect
		$a_01_14 = {62 6f 74 5f 72 61 77 5f 63 6f 6d 6d 61 6e 64 } //1 bot_raw_command
		$a_01_15 = {4b 69 6c 6c 65 64 20 61 6c 6c 20 74 68 72 65 61 64 73 } //1 Killed all threads
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=73
 
}