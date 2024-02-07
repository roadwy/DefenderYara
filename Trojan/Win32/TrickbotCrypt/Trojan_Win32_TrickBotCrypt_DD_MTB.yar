
rule Trojan_Win32_TrickBotCrypt_DD_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {3f 3f 30 43 44 6c 6c 4c 6f 61 64 65 72 40 40 51 41 45 40 50 42 44 5f 4e 40 5a } //01 00  ??0CDllLoader@@QAE@PBD_N@Z
		$a_81_1 = {3f 74 65 72 6d 69 6e 61 74 65 40 40 59 41 58 58 5a } //01 00  ?terminate@@YAXXZ
		$a_81_2 = {21 21 35 72 6e 71 71 7a 7a 21 4f 57 5f 42 3f } //01 00  !!5rnqqzz!OW_B?
		$a_81_3 = {47 75 69 4c 69 62 } //01 00  GuiLib
		$a_81_4 = {4c 6f 63 6b 65 64 } //01 00  Locked
		$a_81_5 = {6b 65 79 62 64 5f 65 76 65 6e 74 } //01 00  keybd_event
		$a_81_6 = {53 65 74 43 61 70 74 75 72 65 } //01 00  SetCapture
		$a_81_7 = {47 65 74 4b 65 79 53 74 61 74 65 } //01 00  GetKeyState
		$a_81_8 = {5a 6f 6f 6d 20 4f 75 74 } //00 00  Zoom Out
	condition:
		any of ($a_*)
 
}