
rule Trojan_Win32_Flyagent_CA_MTB{
	meta:
		description = "Trojan:Win32/Flyagent.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {33 d2 83 fd 10 0f 9d c2 4a 23 d1 4a 45 89 10 89 48 04 83 c0 08 81 fd 00 04 00 00 7c e3 } //01 00 
		$a_00_1 = {8b ca 8b c2 83 e1 07 b3 01 c1 e8 03 d2 e3 8d 44 05 9c 08 18 42 4e 75 e8 } //01 00 
		$a_00_2 = {8b 0d a0 88 4d 00 85 c0 8b 0c 81 7c 19 8b 55 ec 81 c2 5c 01 00 00 8b 72 10 c1 ee 02 3b c6 7d 06 8b 52 08 89 0c 82 40 3b c3 7c d5 } //01 00 
		$a_81_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 64 79 77 74 2e 63 6f 6d 2e 63 6e } //00 00  http://www.dywt.com.cn
	condition:
		any of ($a_*)
 
}