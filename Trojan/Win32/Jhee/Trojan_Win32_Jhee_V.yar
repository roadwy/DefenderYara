
rule Trojan_Win32_Jhee_V{
	meta:
		description = "Trojan:Win32/Jhee.V,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 c9 ff 33 c0 f2 ae f7 d1 49 8b f9 85 ff 7e 26 8b 4c 24 10 8a 54 24 14 53 55 8b c1 2b f1 8b ef 8a 1c 06 32 da 88 18 40 4d 75 f5 5d c6 04 0f 00 5b 5f 5e c2 0c 00 8b 4c 24 10 5f 5e c6 04 08 00 c2 0c 00 } //2
		$a_03_1 = {75 52 8b 8e 4c 01 00 00 8b 96 48 01 00 00 51 8d 46 04 52 50 68 90 01 02 41 00 e8 90 01 02 00 00 83 c4 10 8b ce e8 90 01 02 00 00 85 c0 b8 90 01 02 41 00 75 05 90 00 } //2
		$a_00_2 = {77 69 6e 69 6f 2e 73 79 73 } //1 winio.sys
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_00_2  & 1)*1) >=3
 
}