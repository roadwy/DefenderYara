
rule Backdoor_Win32_Fynloski_R{
	meta:
		description = "Backdoor:Win32/Fynloski.R,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 11 00 00 "
		
	strings :
		$a_00_0 = {41 6e 74 69 56 69 72 75 73 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 } //1 AntiVirusDisableNotify
		$a_00_1 = {41 63 74 69 76 65 4f 6e 6c 69 6e 65 4b 65 79 6c 6f 67 67 65 72 } //1 ActiveOnlineKeylogger
		$a_00_2 = {23 53 65 6e 64 43 6c 69 70 } //1 #SendClip
		$a_00_3 = {23 46 72 65 65 7a 65 49 4f } //1 #FreezeIO
		$a_00_4 = {23 42 4f 54 23 56 69 73 69 74 55 72 6c } //1 #BOT#VisitUrl
		$a_00_5 = {23 42 4f 54 23 4f 70 65 6e 55 72 6c } //1 #BOT#OpenUrl
		$a_00_6 = {23 42 4f 54 23 50 69 6e 67 } //1 #BOT#Ping
		$a_00_7 = {23 42 4f 54 23 52 75 6e 50 72 6f 6d 70 74 } //1 #BOT#RunPrompt
		$a_00_8 = {23 42 4f 54 23 55 52 4c 55 70 64 61 74 65 } //1 #BOT#URLUpdate
		$a_00_9 = {23 42 4f 54 23 55 52 4c 44 6f 77 6e 6c 6f 61 64 } //1 #BOT#URLDownload
		$a_00_10 = {23 42 4f 54 23 43 6c 6f 73 65 53 65 72 76 65 72 } //1 #BOT#CloseServer
		$a_00_11 = {23 52 65 6d 6f 74 65 53 63 72 65 65 6e 53 69 7a 65 } //1 #RemoteScreenSize
		$a_00_12 = {44 44 4f 53 48 54 54 50 46 4c 4f 4f 44 } //1 DDOSHTTPFLOOD
		$a_00_13 = {44 44 4f 53 53 59 4e 46 4c 4f 4f 44 } //1 DDOSSYNFLOOD
		$a_00_14 = {44 44 4f 53 55 44 50 46 4c 4f 4f 44 } //1 DDOSUDPFLOOD
		$a_00_15 = {41 43 54 49 56 45 52 45 4d 4f 54 45 53 48 45 4c 4c } //1 ACTIVEREMOTESHELL
		$a_01_16 = {43 6f 6d 65 74 20 52 41 54 20 4c 65 67 61 63 79 20 69 73 20 61 6c 72 65 61 64 79 20 61 63 74 69 76 65 20 69 6e 20 79 6f 75 72 20 73 79 73 74 65 6d } //65436 Comet RAT Legacy is already active in your system
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1+(#a_01_16  & 1)*65436) >=6
 
}