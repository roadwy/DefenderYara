
rule Trojan_Win32_Trickbot_STZ{
	meta:
		description = "Trojan:Win32/Trickbot.STZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 00 30 00 00 90 02 10 ff d0 50 ff 15 90 01 03 10 90 00 } //01 00 
		$a_00_1 = {41 6e 30 71 54 47 45 72 } //01 00 
		$a_00_2 = {34 54 76 46 50 41 44 36 54 78 4d 79 58 36 7a 67 58 61 6b 62 4d 51 74 51 75 6c 59 53 54 47 6d 68 71 79 34 71 } //01 00 
		$a_00_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}