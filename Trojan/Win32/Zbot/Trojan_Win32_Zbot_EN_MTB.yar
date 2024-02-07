
rule Trojan_Win32_Zbot_EN_MTB{
	meta:
		description = "Trojan:Win32/Zbot.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {50 72 6f 78 79 2d 43 6f 6e 6e 65 63 74 69 6f 6e } //01 00  Proxy-Connection
		$a_81_1 = {7c 7a 6b 72 76 76 63 6e 6d 61 65 62 4e 55 66 } //01 00  |zkrvvcnmaebNUf
		$a_81_2 = {64 63 6d 5c 6e 5c 54 53 } //01 00  dcm\n\TS
		$a_81_3 = {62 61 70 62 58 6c 55 52 } //01 00  bapbXlUR
		$a_81_4 = {66 62 6d 6e 58 5c 56 57 } //00 00  fbmnX\VW
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zbot_EN_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 6e 00 4f 00 66 00 53 00 6f 00 6e 00 2e 00 45 00 58 00 45 00 } //01 00  SonOfSon.EXE
		$a_01_1 = {4d 00 79 00 20 00 53 00 6f 00 6e 00 20 00 69 00 73 00 20 00 6d 00 79 00 20 00 53 00 6f 00 6e 00 } //01 00  My Son is my Son
		$a_01_2 = {5b 00 45 00 53 00 43 00 5d 00 20 00 53 00 74 00 6f 00 70 00 } //01 00  [ESC] Stop
		$a_01_3 = {5b 00 44 00 45 00 4c 00 5d 00 20 00 43 00 6c 00 65 00 61 00 72 00 20 00 6c 00 69 00 73 00 74 00 } //01 00  [DEL] Clear list
		$a_01_4 = {41 75 74 6f 20 43 6c 69 63 6b 65 72 20 56 65 72 20 31 2e 30 } //01 00  Auto Clicker Ver 1.0
		$a_01_5 = {4d 46 43 34 32 } //01 00  MFC42
		$a_01_6 = {6d 6f 75 73 65 5f 65 76 65 6e 74 } //00 00  mouse_event
	condition:
		any of ($a_*)
 
}