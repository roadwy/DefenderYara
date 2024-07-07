
rule Worm_Win32_Seefbot_gen_A{
	meta:
		description = "Worm:Win32/Seefbot.gen!A,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {74 53 6b 4d 61 69 6e 46 6f 72 6d 2e 55 6e 69 63 6f 64 65 43 6c 61 73 73 } //1 tSkMainForm.UnicodeClass
		$a_01_1 = {50 75 54 54 59 } //1 PuTTY
		$a_01_2 = {54 46 72 6d 4d 61 69 6e } //1 TFrmMain
		$a_01_3 = {59 61 68 6f 6f 42 75 64 64 79 4d 61 69 6e } //1 YahooBuddyMain
		$a_01_4 = {4d 53 42 4c 57 69 6e 64 6f 77 43 6c 61 73 73 } //1 MSBLWindowClass
		$a_01_5 = {5f 4f 73 63 61 72 5f 53 74 61 74 75 73 4e 6f 74 69 66 79 } //1 _Oscar_StatusNotify
		$a_01_6 = {5f 5f 6f 78 46 72 61 6d 65 2e 63 6c 61 73 73 5f 5f } //1 __oxFrame.class__
		$a_01_7 = {50 52 49 56 4d 53 47 20 25 73 20 3a 57 47 45 54 20 20 25 73 5c 25 73 20 20 25 73 20 5b 25 73 5d } //1 PRIVMSG %s :WGET  %s\%s  %s [%s]
		$a_01_8 = {6d 61 69 6e 2e 72 65 6d 6f 76 65 } //1 main.remove
		$a_01_9 = {25 73 5c 74 65 6d 70 25 69 25 69 25 69 25 69 2e 62 61 74 } //1 %s\temp%i%i%i%i.bat
		$a_01_10 = {6a 09 5b 99 8b cb f7 f9 52 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}