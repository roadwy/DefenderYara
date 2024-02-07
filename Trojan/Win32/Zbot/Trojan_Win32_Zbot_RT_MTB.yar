
rule Trojan_Win32_Zbot_RT_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 18 8b 45 90 01 01 05 8a a5 08 00 03 45 90 01 01 8b 55 90 01 01 31 02 8d 85 90 01 04 33 c9 ba 90 02 04 e8 90 01 04 8d 85 90 01 04 33 c9 ba 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zbot_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {50 53 41 50 49 2e 44 4c 4c } //01 00  PSAPI.DLL
		$a_81_1 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //01 00  UnhookWindowsHookEx
		$a_81_2 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //01 00  SetWindowsHookExA
		$a_81_3 = {6b 65 79 62 64 5f 65 76 65 6e 74 } //01 00  keybd_event
		$a_81_4 = {4d 61 70 56 69 72 74 75 61 6c 4b 65 79 41 } //01 00  MapVirtualKeyA
		$a_81_5 = {56 6b 4b 65 79 53 63 61 6e 45 78 41 } //05 00  VkKeyScanExA
		$a_81_6 = {68 74 74 70 3a 2f 2f 72 6c 2e 61 6d 6d 79 79 2e 63 6f 6d } //00 00  http://rl.ammyy.com
	condition:
		any of ($a_*)
 
}