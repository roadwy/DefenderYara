
rule Trojan_Win32_Emotet_H_MTB{
	meta:
		description = "Trojan:Win32/Emotet.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 09 00 00 "
		
	strings :
		$a_00_0 = {c7 44 24 0c 40 00 00 00 c7 44 24 08 00 10 00 00 89 44 24 04 c7 04 24 00 00 00 00 } //1
		$a_00_1 = {c7 44 24 0c 40 00 00 00 c7 44 24 08 00 10 00 00 c7 04 24 00 00 00 00 89 44 24 04 } //1
		$a_00_2 = {c7 44 24 0c 40 00 00 00 c7 44 24 08 00 10 00 00 8b 44 24 64 89 44 24 04 c7 04 24 00 00 00 00 } //1
		$a_02_3 = {c7 44 24 0c 40 00 00 00 c7 44 24 08 00 10 00 00 8b 84 24 ?? ?? 00 00 89 44 24 04 c7 04 24 00 00 00 00 } //1
		$a_00_4 = {c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 00 89 44 24 18 } //1
		$a_00_5 = {c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 00 89 04 24 } //1
		$a_00_6 = {c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 00 8b 44 24 3c 89 04 24 } //1
		$a_02_7 = {c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 00 8b 84 24 ?? ?? 00 00 89 04 24 } //1
		$a_00_8 = {53 65 74 55 6e 68 61 6e 64 6c 65 64 45 78 63 65 70 74 69 6f 6e 46 69 6c 74 65 72 } //1 SetUnhandledExceptionFilter
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_02_7  & 1)*1+(#a_00_8  & 1)*1) >=3
 
}