
rule Trojan_Win32_Trickbot_ZC{
	meta:
		description = "Trojan:Win32/Trickbot.ZC,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 6f 72 65 2d 70 61 72 73 65 72 2e 64 6c 6c 00 42 61 6e 52 75 6c 65 00 43 6c 65 61 72 52 75 6c 65 73 00 43 6f 6e 66 69 67 49 6e 69 74 44 70 6f 73 74 00 43 6f 6e 66 69 67 49 6e 69 74 44 79 6e 61 6d 69 63 00 43 6f 6e 66 69 67 49 6e 69 74 53 74 61 74 69 63 00 45 6e 75 6d 44 70 6f 73 74 53 65 72 76 65 72 } //02 00 
		$a_01_1 = {2f 72 63 72 64 2f 00 00 2f 67 65 74 71 2f 00 00 2f 73 6e 61 70 73 68 6f 6f 74 2f } //02 00 
		$a_03_2 = {b8 ab aa aa 2a 8b 90 02 05 2b cf f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 3b f0 90 00 } //00 00 
		$a_00_3 = {5d 04 00 00 } //d9 51 
	condition:
		any of ($a_*)
 
}