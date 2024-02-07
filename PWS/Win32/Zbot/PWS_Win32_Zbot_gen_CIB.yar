
rule PWS_Win32_Zbot_gen_CIB{
	meta:
		description = "PWS:Win32/Zbot.gen!CIB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 55 73 65 72 73 5c 5a 45 55 53 5c 44 65 73 6b 74 6f 70 5c 5a 65 75 73 20 53 6f 75 72 63 65 20 43 6f 64 65 20 32 5c 73 6f 75 72 63 65 5c 63 6c 69 65 6e 74 5c } //01 00  C:\Users\ZEUS\Desktop\Zeus Source Code 2\source\client\
		$a_00_1 = {74 72 79 54 6f 55 70 64 61 74 65 42 6f 74 } //01 00  tryToUpdateBot
		$a_80_2 = {46 61 69 6c 65 64 20 74 6f 20 72 75 6e 20 6e 65 77 20 76 65 72 73 69 6f 6e 20 6f 66 20 62 6f 74 2e } //Failed to run new version of bot.  01 00 
		$a_80_3 = {50 49 44 20 6f 66 20 6e 65 77 20 62 6f 74 20 69 73 20 25 75 2e } //PID of new bot is %u.  01 00 
		$a_80_4 = {46 61 69 6c 65 64 20 74 6f 20 64 6f 77 6e 6c 6f 61 64 20 74 68 65 20 62 6f 74 2e } //Failed to download the bot.  00 00 
		$a_00_5 = {5d 04 00 00 1d } //22 03 
	condition:
		any of ($a_*)
 
}