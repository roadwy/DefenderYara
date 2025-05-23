
rule Trojan_Win32_Viknok_D{
	meta:
		description = "Trojan:Win32/Viknok.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {74 2d c7 00 5c 00 53 00 c7 40 04 65 00 73 00 c7 40 08 73 00 69 00 c7 40 0c 6f 00 6e 00 89 50 10 83 c0 14 83 c1 30 66 89 08 } //1
		$a_01_1 = {b8 bb bb aa ee 8a 5c 31 ff 32 d8 66 89 5c 4a fe 49 75 f2 5b c3 } //1
		$a_01_2 = {8b 46 08 eb 0e f6 40 08 02 74 06 83 78 04 00 } //1
		$a_01_3 = {74 32 66 83 c0 30 c7 02 5c 00 53 00 c7 42 04 65 00 73 00 c7 42 08 73 00 69 00 c7 42 0c 6f 00 6e 00 44 89 42 10 66 89 42 14 48 83 c2 16 } //1
		$a_01_4 = {48 b8 bb bb aa ee 00 00 00 00 8a 5c 31 ff 32 d8 66 89 5c 4a fe 48 ff c9 75 f0 5b c3 } //1
		$a_01_5 = {6c 08 0f 4e 74 4f 70 65 6e 46 69 6c 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}