
rule Trojan_Win32_Trilark_A_dha{
	meta:
		description = "Trojan:Win32/Trilark.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 00 5f 00 53 00 54 00 41 00 52 00 54 00 5f 00 4d 00 59 00 54 00 45 00 53 00 54 00 5f 00 4d 00 41 00 52 00 4b 00 75 00 75 00 75 00 69 00 69 00 5f 00 5f 00 } //02 00 
		$a_01_1 = {25 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 64 65 73 6b 74 6f 70 2e 72 33 75 00 00 00 00 72 62 } //01 00 
		$a_03_2 = {83 e9 08 d1 e9 03 fd 33 f6 85 c9 7e 90 01 01 0f b7 44 72 08 8b e8 81 e5 00 f0 00 00 81 fd 00 30 00 00 75 90 01 01 8b 6c 24 10 25 ff 0f 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}