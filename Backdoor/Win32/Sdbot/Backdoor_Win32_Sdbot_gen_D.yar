
rule Backdoor_Win32_Sdbot_gen_D{
	meta:
		description = "Backdoor:Win32/Sdbot.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,4d 00 4a 00 12 00 00 0a 00 "
		
	strings :
		$a_01_0 = {54 62 62 74 79 72 6f 62 67 2f 32 2e 31 20 28 2b 75 67 67 63 3a 2f 2f 6a 6a 6a 2e 74 62 62 74 79 72 6f 62 67 2e 70 62 7a 2f 6f 62 67 2e 75 67 7a 79 29 } //0a 00  Tbbtyrobg/2.1 (+uggc://jjj.tbbtyrobg.pbz/obg.ugzy)
		$a_01_1 = {47 6f 6f 67 6c 65 62 6f 74 2f 32 2e 31 20 28 2b 68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 62 6f 74 2e 63 6f 6d 2f 62 6f 74 2e 68 74 6d 6c 29 } //0a 00  Googlebot/2.1 (+http://www.googlebot.com/bot.html)
		$a_01_2 = {3a 20 45 78 70 6c 6f 69 74 69 6e 67 2e 2e 20 } //0a 00  : Exploiting.. 
		$a_01_3 = {3a 20 45 78 70 6c 6f 69 74 65 64 20 73 68 61 72 65 20 25 73 5c 43 24 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c } //0a 00  : Exploited share %s\C$\WINDOWS\system32\
		$a_01_4 = {25 73 5c 63 24 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 77 69 6e 73 64 66 2e 65 78 65 } //0a 00  %s\c$\windows\system32\winsdf.exe
		$a_01_5 = {57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 73 72 76 64 6c 6c 33 32 2e 65 78 65 } //05 00  WINDOWS\SYSTEM32\srvdll32.exe
		$a_01_6 = {54 72 79 69 6e 67 20 74 6f 20 69 6e 73 74 61 6c 6c 20 73 70 79 77 61 72 65 20 74 6f 20 67 65 6e 65 72 61 74 65 20 63 61 73 68 2e 2e 2e } //05 00  Trying to install spyware to generate cash...
		$a_01_7 = {44 6f 6e 65 20 77 69 74 68 20 53 59 4e 20 66 6c 6f 6f 64 20 5b } //01 00  Done with SYN flood [
		$a_01_8 = {50 52 49 56 4d 53 47 20 23 72 77 6e 74 20 3a } //01 00  PRIVMSG #rwnt :
		$a_01_9 = {4e 49 43 4b 20 25 73 } //01 00  NICK %s
		$a_01_10 = {55 53 45 52 20 25 73 20 30 20 30 20 3a 25 73 } //01 00  USER %s 0 0 :%s
		$a_01_11 = {4d 4f 44 45 20 25 73 20 2b 69 } //01 00  MODE %s +i
		$a_00_12 = {55 53 45 52 48 4f 53 54 20 25 73 } //01 00  USERHOST %s
		$a_01_13 = {53 65 6e 64 69 6e 67 20 2e 25 64 2e 20 70 69 6e 67 73 20 74 6f 20 25 73 20 28 2e 50 61 63 6b 65 74 20 73 69 7a 65 2e 29 3a 20 25 64 20 28 2e 54 69 6d 65 6f 75 74 2e 29 3a 20 25 64 5b 6d 73 5d } //01 00  Sending .%d. pings to %s (.Packet size.): %d (.Timeout.): %d[ms]
		$a_01_14 = {3a 20 25 73 20 5b 25 73 5d 20 28 2e 4c 6f 63 61 6c 20 49 50 20 61 64 64 72 65 73 73 2e 29 3a 20 25 64 2e 25 64 2e 25 64 2e 25 64 20 28 2e 43 6f 6e 6e 65 63 74 65 64 20 66 72 6f 6d 2e 29 3a 20 25 73 } //01 00  : %s [%s] (.Local IP address.): %d.%d.%d.%d (.Connected from.): %s
		$a_01_15 = {3a 20 25 49 36 34 75 4d 48 7a 20 } //01 00  : %I64uMHz 
		$a_01_16 = {3a 20 25 64 4b 42 20 74 6f 74 61 6c 2c 20 25 64 4b 42 20 66 72 65 65 20 } //01 00  : %dKB total, %dKB free 
		$a_01_17 = {3a 20 57 69 6e 64 6f 77 73 20 25 73 20 5b 25 64 2e 25 64 2c 20 62 75 69 6c 64 20 25 64 5d 20 } //00 00  : Windows %s [%d.%d, build %d] 
	condition:
		any of ($a_*)
 
}