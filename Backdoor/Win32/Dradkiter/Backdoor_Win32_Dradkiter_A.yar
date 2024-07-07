
rule Backdoor_Win32_Dradkiter_A{
	meta:
		description = "Backdoor:Win32/Dradkiter.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 62 42 6f 74 6b 69 6c 6c 65 72 } //4 mobBotkiller
		$a_01_1 = {78 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 2f 00 76 00 62 00 6e 00 74 00 38 00 67 00 75 00 64 00 31 00 64 00 31 00 34 00 7a 00 78 00 38 00 2f 00 61 00 76 00 6b 00 70 00 6c 00 75 00 67 00 69 00 6e 00 2e 00 62 00 69 00 6e 00 } //4 x.com/s/vbnt8gud1d14zx8/avkplugin.bin
		$a_01_2 = {6d 6f 64 4b 55 41 43 } //1 modKUAC
		$a_01_3 = {6d 6f 64 4d 61 67 69 63 4d 75 74 65 78 } //1 modMagicMutex
		$a_01_4 = {41 6e 74 69 5f 44 69 73 61 62 6c 65 72 73 } //1 Anti_Disablers
		$a_01_5 = {42 6f 74 6b 69 6c 6c 65 72 54 69 6d 65 72 } //1 BotkillerTimer
		$a_01_6 = {53 70 72 65 61 64 65 72 73 54 69 6d 65 72 } //1 SpreadersTimer
		$a_01_7 = {23 00 45 00 4f 00 46 00 20 00 44 00 41 00 52 00 4b 00 43 00 4f 00 4d 00 45 00 54 00 20 00 44 00 41 00 54 00 41 00 20 00 2d 00 2d 00 } //1 #EOF DARKCOMET DATA --
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=9
 
}