
rule Backdoor_MacOS_IMFlooder_A_xp{
	meta:
		description = "Backdoor:MacOS/IMFlooder.A!xp,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4d 65 73 73 65 6e 67 65 72 20 49 44 20 6f 66 20 74 68 65 20 76 69 63 74 69 6d } //1 Messenger ID of the victim
		$a_00_1 = {49 4d 20 46 6c 6f 6f 64 56 69 73 69 62 6c 65 } //1 IM FloodVisible
		$a_00_2 = {6d 61 72 6b 2e 6d 61 63 69 6e 74 6f 73 68 40 67 6d 61 69 6c 2e 63 6f 6d } //1 mark.macintosh@gmail.com
		$a_00_3 = {59 61 68 6f 6f 4d 65 73 73 65 6e 67 65 72 43 68 61 74 46 6c 6f 6f 64 65 72 } //1 YahooMessengerChatFlooder
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}