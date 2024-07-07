
rule Backdoor_Win32_IRCbot_DR{
	meta:
		description = "Backdoor:Win32/IRCbot.DR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 83 3c 85 18 90 01 04 0f 84 90 01 01 00 00 00 83 65 fc 00 eb 90 01 01 8b 45 fc 40 89 45 fc 8b 45 f4 ff 34 85 90 01 04 ff 15 90 00 } //2
		$a_01_1 = {8b 4d 08 03 4d f8 8b 55 fc 8a 04 10 32 01 8b 4d f4 } //2
		$a_03_2 = {8b 4d fc 0f be 04 08 f7 d0 8b 4d f4 8b 0c 8d 90 01 04 8b 55 fc 88 04 11 90 00 } //2
		$a_01_3 = {49 6e 74 65 72 6e 65 74 20 53 65 63 75 72 69 74 79 20 53 65 72 76 69 63 65 00 } //1 湉整湲瑥匠捥牵瑩⁹敓癲捩e
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1) >=5
 
}