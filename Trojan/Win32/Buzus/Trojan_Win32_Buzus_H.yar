
rule Trojan_Win32_Buzus_H{
	meta:
		description = "Trojan:Win32/Buzus.H,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {66 81 38 4d 5a 75 90 01 01 60 89 85 90 01 04 8b d0 8b d8 03 40 3c 03 58 78 89 9d 90 01 04 8d 9d 90 01 04 8d bd 90 01 04 8b 33 89 b5 90 01 04 e8 90 01 04 ab 83 c3 04 83 3b 00 90 00 } //02 00 
		$a_03_1 = {c7 45 94 04 00 02 80 c7 45 8c 0a 00 00 00 ba 90 01 04 8d 4d d0 ff 15 90 01 04 8d 55 d0 52 8d 45 9c 50 e8 90 01 04 8d 4d 8c 51 8d 55 9c 52 90 00 } //01 00 
		$a_00_2 = {47 00 62 00 74 00 73 00 6d 00 5f 00 52 00 45 00 2e 00 76 00 62 00 70 00 } //01 00 
		$a_00_3 = {44 00 4a 00 5f 00 53 00 75 00 6e 00 2e 00 76 00 62 00 70 00 } //01 00 
		$a_00_4 = {45 00 72 00 73 00 6d 00 73 00 5f 00 4a 00 4b 00 2e 00 76 00 62 00 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}