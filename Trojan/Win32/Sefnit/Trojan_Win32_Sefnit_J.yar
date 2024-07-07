
rule Trojan_Win32_Sefnit_J{
	meta:
		description = "Trojan:Win32/Sefnit.J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 08 00 00 "
		
	strings :
		$a_01_0 = {c7 45 f8 01 40 00 80 } //1
		$a_01_1 = {0f b6 8c 28 f4 fe ff ff } //1
		$a_01_2 = {88 94 29 f4 fe ff ff } //1
		$a_01_3 = {8b e5 5d ff 25 } //1
		$a_01_4 = {c7 45 f0 70 14 3a 03 } //1
		$a_01_5 = {c7 45 f0 40 92 89 d1 } //1
		$a_01_6 = {c7 45 f0 b0 e7 d9 f5 } //1
		$a_01_7 = {66 c7 45 f4 82 14 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=3
 
}