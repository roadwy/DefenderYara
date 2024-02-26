
rule Trojan_Win32_Zbot_ASD_MTB{
	meta:
		description = "Trojan:Win32/Zbot.ASD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 00 62 00 43 00 39 00 41 00 42 00 33 00 7a 00 2e 00 65 00 78 00 65 00 } //01 00  UbC9AB3z.exe
		$a_01_1 = {49 00 5a 00 79 00 49 00 79 00 44 00 67 00 79 00 2e 00 65 00 78 00 65 00 } //01 00  IZyIyDgy.exe
		$a_01_2 = {37 00 34 00 59 00 39 00 71 00 45 00 70 00 55 00 2e 00 65 00 78 00 65 00 } //01 00  74Y9qEpU.exe
		$a_01_3 = {75 00 6e 00 6e 00 49 00 4a 00 4f 00 6d 00 6f 00 2e 00 65 00 78 00 65 00 } //01 00  unnIJOmo.exe
		$a_01_4 = {53 71 6b 41 31 58 61 38 36 45 55 2e 74 78 74 } //01 00  SqkA1Xa86EU.txt
		$a_01_5 = {44 75 49 43 78 37 46 7a 76 35 2e 69 6e 69 } //01 00  DuICx7Fzv5.ini
		$a_01_6 = {45 76 4a 44 55 37 46 41 77 71 2e 63 66 67 } //00 00  EvJDU7FAwq.cfg
	condition:
		any of ($a_*)
 
}