
rule Trojan_Win32_Sopinar_C{
	meta:
		description = "Trojan:Win32/Sopinar.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {00 00 f3 aa c7 06 63 68 72 6f c7 46 04 6d 65 2e 65 66 c7 46 08 78 65 e8 90 09 03 00 b9 0b 00 } //1
		$a_03_1 = {76 65 6e 64 c7 44 24 ?? 6f 72 5f 69 c7 44 24 ?? 64 00 00 00 90 09 04 00 c7 44 24 } //1
		$a_03_2 = {68 9c f1 01 5d 8b 55 fc 8b 42 04 50 8b 4d fc 8b 11 52 e8 ?? ?? ?? ?? 8b 4d fc 89 41 2c 68 d3 bb 7e 87 } //1
		$a_01_3 = {8a 0c 06 8d 40 01 80 f1 41 88 48 ff 4a 75 f1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}