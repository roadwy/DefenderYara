
rule Backdoor_Win32_IRCbot_gen_Q{
	meta:
		description = "Backdoor:Win32/IRCbot.gen!Q,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 53 6c 61 76 65 2e 44 4c 4c } //01 00  C:\Slave.DLL
		$a_01_1 = {52 65 76 65 72 73 65 20 53 6f 63 6b 73 35 20 53 6c 61 76 65 20 42 6f 74 } //01 00  Reverse Socks5 Slave Bot
		$a_01_2 = {42 79 20 57 69 6e 45 67 67 44 72 6f 70 21 } //01 00  By WinEggDrop!
		$a_01_3 = {50 52 49 56 4d 53 47 20 25 73 20 3a 53 65 74 20 44 4e 53 20 49 50 20 4c 69 73 74 20 54 68 72 75 20 4c 69 6e 6b 20 4c 69 73 74 20 53 75 63 63 65 73 73 66 75 6c 6c 79 } //01 00  PRIVMSG %s :Set DNS IP List Thru Link List Successfully
		$a_01_4 = {50 52 49 56 4d 53 47 20 25 73 20 3a 46 61 69 6c 20 54 6f 20 53 65 6e 64 20 52 65 71 75 65 73 74 20 46 6f 72 20 53 65 74 74 69 6e 67 20 46 69 6c 65 20 50 6f 69 6e 74 65 72 } //01 00  PRIVMSG %s :Fail To Send Request For Setting File Pointer
		$a_01_5 = {50 52 49 56 4d 53 47 20 25 73 20 3a 25 73 20 48 61 73 20 42 65 65 6e 20 48 69 64 64 65 6e 20 53 75 63 63 65 73 73 66 75 6c 6c 79 } //01 00  PRIVMSG %s :%s Has Been Hidden Successfully
		$a_01_6 = {50 52 49 56 4d 53 47 20 25 73 20 3a 4d 6f 64 69 66 79 20 49 52 43 20 42 4f 54 20 45 6e 61 62 6c 65 20 53 75 63 63 65 73 73 66 75 6c 6c 79 } //01 00  PRIVMSG %s :Modify IRC BOT Enable Successfully
		$a_01_7 = {50 52 49 56 4d 53 47 20 25 73 20 3a 49 52 43 20 43 68 61 6e 6e 65 6c 20 4b 65 79 20 4d 75 73 74 20 42 65 20 4c 65 73 73 20 54 68 61 6e 20 33 32 20 43 68 61 72 61 63 74 65 72 73 } //01 00  PRIVMSG %s :IRC Channel Key Must Be Less Than 32 Characters
		$a_01_8 = {52 65 6d 6f 74 65 20 50 72 6f 78 79 20 43 68 61 69 6e 20 49 73 20 54 61 6b 69 6e 67 20 50 6c 61 63 65 } //00 00  Remote Proxy Chain Is Taking Place
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_IRCbot_gen_Q_2{
	meta:
		description = "Backdoor:Win32/IRCbot.gen!Q,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 52 49 56 4d 53 47 20 25 73 20 3a 41 64 64 20 26 20 41 63 74 69 76 61 74 65 20 47 6c 6f 62 61 6c 20 52 65 6d 6f 74 65 20 50 72 6f 78 79 20 43 68 61 69 6e 20 53 75 63 63 65 73 73 66 75 6c 6c 79 } //01 00  PRIVMSG %s :Add & Activate Global Remote Proxy Chain Successfully
		$a_01_1 = {41 6e 74 69 20 48 61 6d 6d 69 6e 67 20 20 20 20 20 3a 20 55 6e 6c 69 6d 69 74 65 64 } //01 00  Anti Hamming     : Unlimited
		$a_01_2 = {46 61 69 6c 20 54 6f 20 55 6e 2d 50 72 6f 74 65 63 74 20 54 68 65 20 50 72 6f 63 65 73 73 20 26 20 46 61 69 6c 20 54 6f 20 53 61 76 65 } //01 00  Fail To Un-Protect The Process & Fail To Save
		$a_01_3 = {41 6e 74 69 20 53 63 61 6e 20 46 65 61 74 75 72 65 20 48 61 73 20 42 65 65 6e 20 44 65 2d 41 63 74 69 76 61 74 65 64 20 42 75 74 20 46 61 69 6c 20 54 6f 20 53 61 76 65 } //01 00  Anti Scan Feature Has Been De-Activated But Fail To Save
		$a_01_4 = {50 52 49 56 4d 53 47 20 25 73 20 3a 43 72 65 61 74 65 20 49 52 43 20 42 6f 74 20 54 68 72 65 61 64 20 53 75 63 63 65 73 73 66 75 6c 6c 79 } //01 00  PRIVMSG %s :Create IRC Bot Thread Successfully
		$a_01_5 = {49 52 43 20 42 6f 74 20 52 75 6e 6e 69 6e 67 20 42 75 74 20 4f 66 66 6c 69 6e 65 } //01 00  IRC Bot Running But Offline
		$a_01_6 = {43 3a 5c 53 6f 63 6b 73 50 72 6f 78 79 2e 44 4c 4c } //01 00  C:\SocksProxy.DLL
		$a_01_7 = {52 65 6d 6f 74 65 20 41 64 6d 69 6e 20 50 6f 72 74 20 4d 75 73 74 20 42 65 20 44 69 67 69 74 73 } //01 00  Remote Admin Port Must Be Digits
		$a_01_8 = {45 76 65 72 79 74 68 69 6e 67 20 54 68 61 74 20 48 61 73 20 41 20 42 65 67 69 6e 6e 69 6e 67 20 48 61 73 20 41 6e 20 45 6e 64 } //00 00  Everything That Has A Beginning Has An End
	condition:
		any of ($a_*)
 
}