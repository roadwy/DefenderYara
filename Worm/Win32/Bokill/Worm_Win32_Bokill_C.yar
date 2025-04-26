
rule Worm_Win32_Bokill_C{
	meta:
		description = "Worm:Win32/Bokill.C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {46 61 63 65 62 6f 6f 6b 53 70 72 65 61 64 } //1 FacebookSpread
		$a_01_1 = {54 77 69 74 74 65 72 53 70 72 65 61 64 65 72 } //1 TwitterSpreader
		$a_01_2 = {42 6f 74 6b 69 6c 6c 65 72 44 65 6c 61 79 72 65 73 74 61 72 74 } //1 BotkillerDelayrestart
		$a_01_3 = {43 6f 6e 74 61 64 6f 72 55 41 43 } //1 ContadorUAC
		$a_01_4 = {53 65 6e 64 6d 65 73 73 61 67 65 53 70 72 65 61 64 46 61 63 65 62 6f 6f 6b } //1 SendmessageSpreadFacebook
		$a_01_5 = {55 00 6e 00 69 00 74 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //1 UnitKeylogger
		$a_01_6 = {4b 69 6c 6c 53 65 72 76 69 63 65 61 76 } //1 KillServiceav
		$a_01_7 = {75 73 62 73 70 72 65 61 64 } //1 usbspread
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=6
 
}