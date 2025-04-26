
rule Trojan_Win32_Alureon_DE{
	meta:
		description = "Trojan:Win32/Alureon.DE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {50 57 c6 45 ?? 43 c6 45 ?? 63 c6 45 ?? 5a c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 6f c6 45 ?? 44 c6 45 ?? 61 c6 45 ?? 74 c6 45 ?? 61 c6 45 ?? 00 } //1
		$a_03_1 = {6a 6f 58 6a 74 66 89 45 ?? 58 6a 67 } //1
		$a_01_2 = {50 b8 a9 32 8c 7a ff d0 } //1
		$a_03_3 = {8b 43 08 01 45 08 81 73 0c ?? ?? ?? ?? 8b 5b 0c 8b 46 2c 03 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}