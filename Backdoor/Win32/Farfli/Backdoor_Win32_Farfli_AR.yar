
rule Backdoor_Win32_Farfli_AR{
	meta:
		description = "Backdoor:Win32/Farfli.AR,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {75 73 65 72 20 67 75 65 73 74 20 72 61 74 70 70 20 26 26 20 6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 20 67 75 65 73 74 } //0a 00  user guest ratpp && net localgroup administrators guest
		$a_01_1 = {43 4f 4d 4d 41 4e 44 5f 55 4e 50 41 43 4b 5f 52 41 52 20 72 65 76 65 } //0a 00  COMMAND_UNPACK_RAR reve
		$a_01_2 = {3c 48 31 3e 34 30 33 20 46 6f 72 62 69 64 64 65 6e 3c 2f 48 31 3e } //01 00  <H1>403 Forbidden</H1>
		$a_03_3 = {ff 61 c6 85 90 01 01 ff ff ff 76 c6 85 90 01 01 ff ff ff 70 c6 85 90 01 01 ff ff ff 2e c6 85 90 01 01 ff ff ff 65 c6 85 90 01 01 ff ff ff 78 c6 85 90 01 01 ff ff ff 65 90 00 } //01 00 
		$a_03_4 = {ff 4b c6 85 90 01 01 ff ff ff 76 c6 85 90 01 01 ff ff ff 4d c6 85 90 01 01 ff ff ff 6f c6 85 90 01 01 ff ff ff 6e c6 85 90 01 01 ff ff ff 58 c6 85 90 01 01 ff ff ff 50 c6 85 90 01 01 ff ff ff 2e c6 85 90 01 01 ff ff ff 65 c6 85 90 01 01 ff ff ff 78 c6 85 90 01 01 ff ff ff 65 90 00 } //01 00 
		$a_03_5 = {ff 52 c6 85 90 01 01 ff ff ff 61 c6 85 90 01 01 ff ff ff 76 c6 85 90 01 01 ff ff ff 4d c6 85 90 01 01 ff ff ff 6f c6 85 90 01 01 ff ff ff 6e c6 85 90 01 01 ff ff ff 44 c6 85 90 01 01 ff ff ff 2e c6 85 90 01 01 ff ff ff 65 c6 85 90 01 01 ff ff ff 78 c6 85 90 01 01 ff ff ff 65 90 00 } //01 00 
		$a_03_6 = {ff 4d c6 85 90 01 01 ff ff ff 63 c6 85 90 01 01 ff ff ff 73 c6 85 90 01 01 ff ff ff 68 c6 85 90 01 01 ff ff ff 69 c6 85 90 01 01 ff ff ff 65 c6 85 90 01 01 ff ff ff 6c c6 85 90 01 01 ff ff ff 64 c6 85 90 01 01 ff ff ff 2e c6 85 90 01 01 ff ff ff 65 c6 85 90 01 01 ff ff ff 78 c6 85 90 01 01 ff ff ff 65 90 00 } //01 00 
		$a_03_7 = {ff 65 c6 85 90 01 01 ff ff ff 67 c6 85 90 01 01 ff ff ff 75 c6 85 90 01 01 ff ff ff 69 c6 85 90 01 01 ff ff ff 2e c6 85 90 01 01 ff ff ff 65 c6 85 90 01 01 ff ff ff 78 c6 85 90 01 01 ff ff ff 65 90 00 } //01 00 
		$a_03_8 = {ff 6b c6 85 90 01 01 ff ff ff 6e c6 85 90 01 01 ff ff ff 73 c6 85 90 01 01 ff ff ff 64 c6 85 90 01 01 ff ff ff 74 c6 85 90 01 01 ff ff ff 72 c6 85 90 01 01 ff ff ff 61 c6 85 90 01 01 ff ff ff 79 c6 85 90 01 01 ff ff ff 2e c6 85 90 01 01 ff ff ff 65 c6 85 90 01 01 ff ff ff 78 c6 85 90 01 01 ff ff ff 65 90 00 } //01 00 
		$a_03_9 = {ff 61 c6 85 90 01 01 ff ff ff 76 c6 85 90 01 01 ff ff ff 63 c6 85 90 01 01 ff ff ff 65 c6 85 90 01 01 ff ff ff 6e c6 85 90 01 01 ff ff ff 74 c6 85 90 01 01 ff ff ff 65 c6 85 90 01 01 ff ff ff 72 c6 85 90 01 01 ff ff ff 2e c6 85 90 01 01 ff ff ff 65 c6 85 90 01 01 ff ff ff 78 c6 85 90 01 01 ff ff ff 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}