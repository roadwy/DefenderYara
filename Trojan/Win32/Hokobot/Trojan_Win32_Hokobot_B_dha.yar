
rule Trojan_Win32_Hokobot_B_dha{
	meta:
		description = "Trojan:Win32/Hokobot.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 53 65 72 76 69 63 65 73 } //01 00  MicrosoftServices
		$a_01_1 = {2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 50 49 44 } //01 00  /c taskkill /f /PID
		$a_01_2 = {26 63 6f 70 79 6d 65 3d 35 26 78 70 68 70 66 69 6c 65 3d } //01 00  &copyme=5&xphpfile=
		$a_01_3 = {44 4c 44 2d 53 3a } //01 00  DLD-S:
		$a_01_4 = {44 4c 44 2d 45 3a } //01 00  DLD-E:
		$a_00_5 = {68 74 74 70 3a 2f 2f 6d 61 6b 74 6f 6f 62 2e 79 61 68 6f 6f 2e 63 6f 6d 2f } //00 00  http://maktoob.yahoo.com/
		$a_00_6 = {5d 04 00 00 } //45 33 
	condition:
		any of ($a_*)
 
}