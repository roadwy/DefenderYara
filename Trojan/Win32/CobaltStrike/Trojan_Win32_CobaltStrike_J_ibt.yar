
rule Trojan_Win32_CobaltStrike_J_ibt{
	meta:
		description = "Trojan:Win32/CobaltStrike.J!ibt,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 03 00 "
		
	strings :
		$a_80_0 = {74 65 73 74 2e 64 6c 6c 00 74 6f 6d 6d 79 } //test.dll  03 00 
		$a_80_1 = {73 68 65 6c 6c 63 6f 64 65 65 78 65 63 75 74 65 } //shellcodeexecute  03 00 
		$a_02_2 = {6a 40 68 00 10 00 00 68 90 01 04 6a 00 ff 15 90 00 } //01 00 
		$a_00_3 = {8b c6 8b 7d fc 99 f7 fb 8a 04 97 30 04 0e 46 3b 75 0c 7c ec } //01 00 
		$a_02_4 = {45 fc 99 f7 7d 0c 90 01 03 33 0c 90 90 01 01 55 10 03 55 fc 88 0a eb cf 90 00 } //01 00 
		$a_00_5 = {6b 75 77 4b 58 52 49 4c 48 75 59 69 4e 44 45 34 68 31 31 4c 68 6d 49 54 63 56 78 30 44 49 4f 73 35 6b 72 62 73 41 6f 74 4c 65 4a 64 59 4e } //00 00  kuwKXRILHuYiNDE4h11LhmITcVx0DIOs5krbsAotLeJdYN
		$a_00_6 = {5d 04 00 00 ed 73 04 80 5c } //26 00 
	condition:
		any of ($a_*)
 
}