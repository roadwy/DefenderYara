
rule Trojan_Win32_Cutwail_A{
	meta:
		description = "Trojan:Win32/Cutwail.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 7d fc 8b 77 24 03 75 f4 03 75 08 33 c0 66 8b 06 c1 e0 02 8b 75 fc 8b 76 1c 03 75 08 03 f0 8b 06 03 45 08 } //02 00 
		$a_01_1 = {ff 50 8b c9 58 8b c9 50 2b f6 58 8b c9 68 83 ea 23 01 8b c9 8f 45 fc 8b d0 eb 24 } //01 00 
		$a_00_2 = {73 64 6c 74 68 71 30 72 37 33 34 39 35 } //01 00  sdlthq0r73495
		$a_00_3 = {69 6d 73 73 79 73 74 65 6d } //01 00  imssystem
		$a_00_4 = {64 74 68 33 34 39 30 35 79 33 34 35 6f } //00 00  dth34905y345o
	condition:
		any of ($a_*)
 
}