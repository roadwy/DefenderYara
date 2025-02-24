
rule Trojan_Win32_AccessibilityEscalation_C{
	meta:
		description = "Trojan:Win32/AccessibilityEscalation.C,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 07 00 00 "
		
	strings :
		$a_00_0 = {75 00 74 00 69 00 6c 00 6d 00 61 00 6e 00 2e 00 65 00 78 00 65 00 } //1 utilman.exe
		$a_00_1 = {73 00 65 00 74 00 68 00 63 00 2e 00 65 00 78 00 65 00 } //1 sethc.exe
		$a_00_2 = {6f 00 73 00 6b 00 2e 00 65 00 78 00 65 00 } //1 osk.exe
		$a_00_3 = {6d 00 61 00 67 00 6e 00 69 00 66 00 79 00 2e 00 65 00 78 00 65 00 } //1 magnify.exe
		$a_00_4 = {6e 00 61 00 72 00 72 00 61 00 74 00 6f 00 72 00 2e 00 65 00 78 00 65 00 } //1 narrator.exe
		$a_00_5 = {64 00 69 00 73 00 70 00 6c 00 61 00 79 00 73 00 77 00 69 00 74 00 63 00 68 00 2e 00 65 00 78 00 65 00 } //1 displayswitch.exe
		$a_00_6 = {61 00 74 00 62 00 72 00 6f 00 6b 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 atbroker.exe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=1
 
}