
rule Trojan_Win32_Busky_EF{
	meta:
		description = "Trojan:Win32/Busky.EF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {5d 89 45 b1 c6 45 90 01 01 68 c6 45 90 01 01 74 c6 45 90 01 01 74 c6 45 90 01 01 70 c6 45 90 01 01 3a c6 45 90 01 01 2f c6 45 90 01 01 2f 90 00 } //1
		$a_00_1 = {8b 75 e8 83 c6 01 80 3e 45 74 02 eb 0b 8b 75 e8 83 c6 02 80 3e 42 74 02 eb 0b 8b 75 e8 83 c6 03 80 3e 4d 74 02 eb 0b 8b 75 e8 83 c6 04 80 3e 49 74 02 eb 0b 8b 75 e8 } //1
		$a_00_2 = {c1 6d dc 0a 8b 45 dc 31 45 e8 8b 45 e8 89 45 d8 c1 65 d8 03 8b 45 d8 01 45 e8 8b 45 e8 89 45 d4 c1 6d d4 06 8b 45 d4 31 45 e8 8b 45 e8 89 45 d0 c1 65 d0 0b } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}