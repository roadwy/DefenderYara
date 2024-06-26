
rule Backdoor_Win32_Simbot{
	meta:
		description = "Backdoor:Win32/Simbot,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_02_0 = {56 8b 45 0c 8d 8d e8 fe ff ff 8d 34 03 e8 90 01 04 30 06 43 3b 5d 10 7c e7 5e 90 00 } //01 00 
		$a_01_1 = {2f 25 73 2e 70 68 70 3f 69 64 3d 25 30 36 64 25 73 } //01 00  /%s.php?id=%06d%s
		$a_01_2 = {25 63 25 63 25 63 25 63 25 63 25 63 2e 65 78 65 } //01 00  %c%c%c%c%c%c.exe
		$a_01_3 = {25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 } //00 00  %02X-%02X-%02X-%02X-%02X-%02X
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Simbot_2{
	meta:
		description = "Backdoor:Win32/Simbot,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 0e 00 00 0f 00 "
		
	strings :
		$a_03_0 = {2f 66 63 2e c7 45 90 01 01 61 73 70 3f c7 45 90 01 01 65 73 74 3d c7 45 fc 90 01 01 00 cc cc 90 00 } //05 00 
		$a_00_1 = {5c 6e 74 75 73 65 72 2e 63 66 67 22 2c 43 6f 6e 66 69 67 } //05 00  \ntuser.cfg",Config
		$a_00_2 = {25 30 32 78 2d 25 30 32 78 2d 25 30 32 78 2d 25 30 32 78 2d 25 30 32 78 2d 25 30 32 78 } //05 00  %02x-%02x-%02x-%02x-%02x-%02x
		$a_00_3 = {25 73 25 73 25 73 26 68 6e 25 73 25 73 20 26 68 61 25 73 25 73 20 26 68 6d 25 73 25 73 20 26 68 76 25 73 25 73 20 26 68 62 25 73 25 73 20 26 68 70 25 73 25 73 } //01 00  %s%s%s&hn%s%s &ha%s%s &hm%s%s &hv%s%s &hb%s%s &hp%s%s
		$a_00_4 = {73 6f 70 68 6f 73 } //01 00  sophos
		$a_00_5 = {6b 61 73 70 65 72 73 6b 79 } //01 00  kaspersky
		$a_00_6 = {74 72 65 6e 64 } //01 00  trend
		$a_00_7 = {70 61 6e 64 61 } //01 00  panda
		$a_00_8 = {6d 61 63 66 65 65 } //01 00  macfee
		$a_00_9 = {73 79 6d 61 6e 74 65 63 } //01 00  symantec
		$a_00_10 = {6e 6f 72 74 6f 6e } //01 00  norton
		$a_00_11 = {61 76 69 72 61 } //01 00  avira
		$a_00_12 = {61 76 61 73 74 } //01 00  avast
		$a_00_13 = {33 36 30 73 64 } //00 00  360sd
	condition:
		any of ($a_*)
 
}