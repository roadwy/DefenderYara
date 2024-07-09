
rule Trojan_Win32_Nahip_A{
	meta:
		description = "Trojan:Win32/Nahip.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {4e 79 05 be 18 00 00 00 8a 54 34 ?? 8a 1c 01 32 da 88 1c 01 41 3b cf 7c e7 } //2
		$a_01_1 = {b3 2e b1 78 b2 72 3b c7 89 7d fc c7 85 98 fe ff ff 28 01 00 00 c6 45 d0 77 c6 45 d1 69 c6 45 d3 6c } //1
		$a_01_2 = {b3 65 8d 4c 24 48 c6 44 24 10 77 85 c9 c6 44 24 11 69 c6 44 24 12 6e c6 44 24 13 6c } //1
		$a_01_3 = {72 00 75 00 6e 00 61 00 73 00 00 00 25 73 0a 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}