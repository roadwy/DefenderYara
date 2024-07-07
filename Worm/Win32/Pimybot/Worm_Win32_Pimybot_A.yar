
rule Worm_Win32_Pimybot_A{
	meta:
		description = "Worm:Win32/Pimybot.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 6c 61 73 68 62 6f 74 5c 69 6e 66 65 63 74 2e 63 70 70 } //1 flashbot\infect.cpp
		$a_01_1 = {54 72 79 69 6e 67 20 74 6f 20 69 6e 66 65 63 74 20 42 4f 54 21 } //1 Trying to infect BOT!
		$a_01_2 = {49 6e 66 65 63 74 54 68 72 65 61 64 } //1 InfectThread
		$a_01_3 = {5b 46 41 43 45 42 4f 4f 4b 5d 20 41 55 54 4f 4c 4f 41 44 20 45 52 52 4f 52 20 61 74 } //1 [FACEBOOK] AUTOLOAD ERROR at
		$a_01_4 = {44 72 69 76 65 20 25 73 20 69 73 20 61 6c 72 65 61 64 79 20 69 6e 66 65 63 74 65 64 2c 20 69 6e 66 65 63 74 69 6e 67 20 72 65 6d 61 69 6e 69 6e 67 20 66 69 6c 65 73 } //1 Drive %s is already infected, infecting remaining files
		$a_03_5 = {8b 45 18 c7 00 00 00 00 00 8b 45 90 01 01 6b c0 ff 8b 4d 10 66 89 01 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=4
 
}