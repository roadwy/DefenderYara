
rule Trojan_Win32_Adept_B{
	meta:
		description = "Trojan:Win32/Adept.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 75 08 83 7d 0c 00 7c 05 4a 78 1a eb 11 8a 04 31 0a c0 74 04 3c ?? 75 06 80 34 31 ?? eb 07 80 34 31 ?? 41 eb } //1
		$a_00_1 = {8b 5d 0c 8b 75 08 8a 0e d3 c1 83 c2 90 01 01 33 ca 33 c1 46 4b 75 } //1
		$a_00_2 = {8b 43 3c 66 81 3c 18 50 45 0f 85 a2 00 00 00 8b 4c 18 78 0b c9 0f 84 96 00 00 00 83 7d 10 00 0f 84 8c 00 00 00 03 cb 8b 51 18 } //1
		$a_00_3 = {33 d2 b9 30 00 00 00 64 ff 34 11 58 85 c0 78 17 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}