
rule Backdoor_Win32_IRCbot_AN{
	meta:
		description = "Backdoor:Win32/IRCbot.AN,SIGNATURE_TYPE_PEHSTR_EXT,ffffffbf 05 79 05 16 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1000 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 69 72 63 61 64 64 6f 6e 2e 65 78 65 } //100 c:\windows\system32\ircaddon.exe
		$a_00_2 = {2d 6c 61 6d 65 72 7a } //100 -lamerz
		$a_00_3 = {73 74 61 72 74 62 6f 74 6f 69 } //100 startbotoi
		$a_00_4 = {73 74 6f 70 62 6f 74 6f 69 } //40 stopbotoi
		$a_00_5 = {73 6f 63 6b 65 74 20 62 75 7a 7a 6f 72 } //40 socket buzzor
		$a_00_6 = {48 6f 6e 65 79 20 47 6f 6e 6e 65 63 74 69 6e 67 } //40 Honey Gonnecting
		$a_00_7 = {65 6e 74 65 72 6e 6f 74 } //10 enternot
		$a_00_8 = {4e 49 43 4b 20 25 73 } //10 NICK %s
		$a_00_9 = {4a 4f 49 4e 20 25 73 20 25 73 } //10 JOIN %s %s
		$a_00_10 = {50 4f 4e 47 20 25 73 } //10 PONG %s
		$a_00_11 = {55 53 45 52 20 25 73 20 22 6e 69 63 6b 22 20 22 25 73 22 20 3a 25 73 } //10 USER %s "nick" "%s" :%s
		$a_00_12 = {5b 4e 75 6d 20 4c 6f 63 6b 5d } //10 [Num Lock]
		$a_00_13 = {5b 44 6f 77 6e 5d } //10 [Down]
		$a_00_14 = {5b 52 69 67 68 74 5d } //10 [Right]
		$a_00_15 = {5b 4c 65 66 74 5d } //10 [Left]
		$a_00_16 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_00_17 = {4d 69 63 72 6f 73 6f 66 74 20 49 6e 73 74 61 6e 74 20 4d 65 73 73 61 67 69 6e 67 20 50 72 6f 74 6f 63 6f 6c } //1 Microsoft Instant Messaging Protocol
		$a_00_18 = {4d 69 63 72 6f 73 6f 66 74 20 49 49 53 20 35 2e 30 } //1 Microsoft IIS 5.0
		$a_00_19 = {50 52 49 56 4d 53 47 20 25 73 20 3a 52 50 43 4e 55 4b 45 } //200 PRIVMSG %s :RPCNUKE
		$a_00_20 = {76 75 6c 6e 65 72 61 62 6c 65 20 73 61 6d 62 61 } //200 vulnerable samba
		$a_02_21 = {6e 65 74 20 73 68 61 72 65 20 2f 64 65 6c 65 74 65 20 ?? 24 } //50
	condition:
		((#a_00_0  & 1)*1000+(#a_00_1  & 1)*100+(#a_00_2  & 1)*100+(#a_00_3  & 1)*100+(#a_00_4  & 1)*40+(#a_00_5  & 1)*40+(#a_00_6  & 1)*40+(#a_00_7  & 1)*10+(#a_00_8  & 1)*10+(#a_00_9  & 1)*10+(#a_00_10  & 1)*10+(#a_00_11  & 1)*10+(#a_00_12  & 1)*10+(#a_00_13  & 1)*10+(#a_00_14  & 1)*10+(#a_00_15  & 1)*10+(#a_00_16  & 1)*1+(#a_00_17  & 1)*1+(#a_00_18  & 1)*1+(#a_00_19  & 1)*200+(#a_00_20  & 1)*200+(#a_02_21  & 1)*50) >=1401
 
}