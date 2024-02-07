
rule Backdoor_Win32_IRCbot_CC{
	meta:
		description = "Backdoor:Win32/IRCbot.CC,SIGNATURE_TYPE_PEHSTR,41 00 3c 00 18 00 00 0f 00 "
		
	strings :
		$a_01_0 = {5c 70 68 6f 74 6f 20 61 6c 62 75 6d 2e 7a 69 70 } //0f 00  \photo album.zip
		$a_01_1 = {70 68 6f 74 6f 20 61 6c 62 75 6d 32 30 30 37 2e 70 69 66 } //0a 00  photo album2007.pif
		$a_01_2 = {50 52 49 56 4d 53 47 20 25 73 20 3a 4d 53 4e 20 77 6f 72 6d 20 73 65 6e 74 20 74 6f 3a 20 25 64 20 63 6f 6e 74 61 63 74 73 } //05 00  PRIVMSG %s :MSN worm sent to: %d contacts
		$a_01_3 = {50 52 49 56 4d 53 47 20 25 73 20 3a 20 77 6f 77 3a 20 25 73 20 25 73 3a 25 73 } //05 00  PRIVMSG %s : wow: %s %s:%s
		$a_01_4 = {50 52 49 56 4d 53 47 20 25 73 20 3a 45 78 65 63 75 74 65 64 20 5b 25 73 5d } //05 00  PRIVMSG %s :Executed [%s]
		$a_01_5 = {50 52 49 56 4d 53 47 20 25 73 20 3a 46 61 69 6c 65 64 20 5b 25 73 5d } //05 00  PRIVMSG %s :Failed [%s]
		$a_01_6 = {4e 49 43 4b 20 5b 25 73 5d 5b 25 69 48 5d 25 73 } //05 00  NICK [%s][%iH]%s
		$a_01_7 = {6e 65 74 20 73 74 6f 70 20 22 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 22 } //05 00  net stop "Security Center"
		$a_01_8 = {6e 65 74 20 73 74 6f 70 20 53 68 61 72 65 64 41 63 63 65 73 73 } //01 00  net stop SharedAccess
		$a_01_9 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 } //01 00  SYSTEM\CurrentControlSet\Services\SharedAccess
		$a_01_10 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 77 75 61 75 73 65 72 76 } //01 00  SYSTEM\CurrentControlSet\Services\wuauserv
		$a_01_11 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 77 73 63 73 76 63 } //01 00  SYSTEM\CurrentControlSet\Services\wscsvc
		$a_01_12 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 68 65 6c 6c 53 65 72 76 69 63 65 4f 62 6a 65 63 74 44 65 6c 61 79 4c 6f 61 64 } //01 00  Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
		$a_01_13 = {4c 6d 66 61 6f 20 68 65 79 20 69 6d 20 73 65 6e 64 69 6e 67 20 6d 79 20 6e 65 77 20 70 68 6f 74 6f 20 61 6c 62 75 6d 2c 20 53 6f 6d 65 20 62 61 72 65 20 66 75 6e 6e 79 20 70 69 63 74 75 72 65 73 21 } //01 00  Lmfao hey im sending my new photo album, Some bare funny pictures!
		$a_01_14 = {6c 6f 6c 20 6d 79 20 73 69 73 74 65 72 20 77 61 6e 74 73 20 6d 65 20 74 6f 20 73 65 6e 64 20 79 6f 75 20 74 68 69 73 20 70 68 6f 74 6f 20 61 6c 62 75 6d } //01 00  lol my sister wants me to send you this photo album
		$a_01_15 = {48 65 79 20 69 20 62 65 65 6e 20 64 6f 69 6e 67 20 70 68 6f 74 6f 20 61 6c 62 75 6d 21 20 53 68 6f 75 6c 64 20 73 65 65 20 65 6d 20 6c 6f 4c 21 20 61 63 63 65 70 74 20 70 6c 65 61 73 65 20 6d 61 74 65 20 3a 29 } //01 00  Hey i been doing photo album! Should see em loL! accept please mate :)
		$a_01_16 = {48 45 59 20 6c 6f 6c 20 69 27 76 65 20 64 6f 6e 65 20 61 20 6e 65 77 20 70 68 6f 74 6f 20 61 6c 62 75 6d 20 21 3a 29 20 53 65 63 6f 6e 64 20 69 6c 6c 20 66 69 6e 64 20 66 69 6c 65 20 61 6e 64 20 73 65 6e 64 20 79 6f 75 20 69 74 2e } //01 00  HEY lol i've done a new photo album !:) Second ill find file and send you it.
		$a_01_17 = {48 65 79 20 77 61 6e 6e 61 20 73 65 65 20 6d 79 20 6e 65 77 20 70 68 6f 74 6f 20 61 6c 62 75 6d 3f } //01 00  Hey wanna see my new photo album?
		$a_01_18 = {4f 4d 47 20 6a 75 73 74 20 61 63 63 65 70 74 20 70 6c 65 61 73 65 20 69 74 73 20 6f 6e 6c 79 20 6d 79 20 70 68 6f 74 6f 20 61 6c 62 75 6d 21 21 } //01 00  OMG just accept please its only my photo album!!
		$a_01_19 = {48 65 79 20 61 63 63 65 70 74 20 6d 79 20 70 68 6f 74 6f 20 61 6c 62 75 6d 2c 20 4e 69 63 65 20 6e 65 77 20 70 69 63 73 20 6f 66 20 6d 65 20 61 6e 64 20 6d 79 20 66 72 69 65 6e 64 73 20 61 6e 64 20 73 74 75 66 66 20 61 6e 64 20 77 68 65 6e 20 69 20 77 61 73 20 79 6f 75 6e 67 20 6c 6f 6c 2e 2e 2e } //01 00  Hey accept my photo album, Nice new pics of me and my friends and stuff and when i was young lol...
		$a_01_20 = {48 65 79 20 6a 75 73 74 20 66 69 6e 69 73 68 65 64 20 6e 65 77 20 70 68 6f 74 6f 20 61 6c 62 75 6d 21 20 3a 29 20 6d 69 67 68 74 20 62 65 20 61 20 66 65 77 20 6e 75 64 65 73 20 3b 29 20 6c 6f 6c 2e 2e 2e } //01 00  Hey just finished new photo album! :) might be a few nudes ;) lol...
		$a_01_21 = {68 65 79 20 79 6f 75 20 67 6f 74 20 61 20 70 68 6f 74 6f 20 61 6c 62 75 6d 3f 20 61 6e 79 77 61 79 73 20 68 65 72 65 73 20 6d 79 20 6e 65 77 20 70 68 6f 74 6f 20 61 6c 62 75 6d 20 3a 29 20 61 63 63 65 70 74 20 6b 3f } //01 00  hey you got a photo album? anyways heres my new photo album :) accept k?
		$a_01_22 = {68 65 79 20 6d 61 6e 20 61 63 63 65 70 74 20 6d 79 20 6e 65 77 20 70 68 6f 74 6f 20 61 6c 62 75 6d 2e 2e 20 3a 28 20 6d 61 64 65 20 69 74 20 66 6f 72 20 79 61 68 2c 20 62 65 65 6e 20 64 6f 69 6e 67 20 70 69 63 74 75 72 65 20 73 74 6f 72 79 20 6f 66 20 6d 79 20 6c 69 66 65 20 6c 6f 6c 2e 2e } //01 00  hey man accept my new photo album.. :( made it for yah, been doing picture story of my life lol..
		$a_01_23 = {6c 6f 6c 20 6c 6f 6c 20 6c 6f 6c 20 3a 73 68 61 64 6f 77 62 6f 74 32 } //00 00  lol lol lol :shadowbot2
	condition:
		any of ($a_*)
 
}