
rule Trojan_Win32_Sryndort_A{
	meta:
		description = "Trojan:Win32/Sryndort.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 4d e8 2b c8 46 8a 51 19 88 54 3e ff eb 90 01 01 8a 04 1e 8d 4d ec 50 e8 90 00 } //2
		$a_01_1 = {8b 5d 08 83 c9 ff 8b fb 33 c0 f2 ae f7 d1 49 c6 45 fc 02 51 89 4d 08 e8 } //1
		$a_01_2 = {8b 44 b8 fc 8b 5c 24 2c 33 d2 89 44 24 28 8a 54 24 2a 0f be 1b 0f be 92 } //1
		$a_01_3 = {8b 44 24 30 c1 e2 08 33 d3 8b 18 33 da 89 18 8b 5c 24 2c 43 83 ff 08 89 5c 24 2c 74 2b } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}