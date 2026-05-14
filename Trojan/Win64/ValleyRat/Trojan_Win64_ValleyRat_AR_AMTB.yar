
rule Trojan_Win64_ValleyRat_AR_AMTB{
	meta:
		description = "Trojan:Win64/ValleyRat.AR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {44 6f 77 6e 6c 6f 61 64 65 72 } //Downloader  1
		$a_80_1 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 76 65 6e 77 69 6e 2e 6c 6f 63 6b } //C:\Users\Public\venwin.lock  1
		$a_80_2 = {5b 43 6d 64 48 61 6e 64 6c 65 72 5d 20 6d 6f 6e 69 74 6f 72 20 70 72 6f 67 72 65 73 73 20 73 74 61 72 74 65 64 2e } //[CmdHandler] monitor progress started.  1
		$a_80_3 = {5b 43 6d 64 48 61 6e 64 6c 65 72 5d 20 55 53 44 54 20 68 69 6a 61 63 6b 20 73 74 61 72 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //[CmdHandler] USDT hijack started successfully  1
		$a_80_4 = {5b 4b 65 79 62 6f 61 72 64 52 65 63 6f 72 64 5d 20 46 61 69 6c 65 64 20 74 6f 20 65 6e 61 62 6c 65 20 6f 66 66 6c 69 6e 65 20 6b 65 79 62 6f 61 72 64 } //[KeyboardRecord] Failed to enable offline keyboard  1
		$a_80_5 = {45 6e 61 62 6c 65 4f 66 66 6c 69 6e 65 4b 65 79 62 6f 61 72 64 } //EnableOfflineKeyboard  1
		$a_80_6 = {2e 3f 41 56 4b 65 79 62 6f 61 72 64 52 65 63 6f 72 64 40 40 } //.?AVKeyboardRecord@@  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}