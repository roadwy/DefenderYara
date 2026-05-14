
rule Trojan_Win32_Vidar_SJ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {0f b6 2c 0b 0f b6 34 13 31 f5 95 88 04 19 95 43 } //1
		$a_81_1 = {6d 61 69 6e 2e 42 72 69 6c 6c 69 61 6e 74 } //1 main.Brilliant
		$a_81_2 = {6d 61 69 6e 2e 44 69 73 63 75 73 73 69 6e 67 } //1 main.Discussing
		$a_81_3 = {6d 61 69 6e 2e 43 6f 6e 76 65 72 74 65 64 } //1 main.Converted
		$a_81_4 = {6d 61 69 6e 2e 47 75 61 72 61 6e 74 65 65 73 } //1 main.Guarantees
		$a_81_5 = {6d 61 69 6e 2e 57 6f 6e 64 65 72 69 6e 67 } //1 main.Wondering
		$a_81_6 = {6d 61 69 6e 2e 54 72 61 6e 73 6c 61 74 65 64 } //1 main.Translated
		$a_81_7 = {6d 61 69 6e 2e 46 72 65 64 65 72 69 63 6b } //1 main.Frederick
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}