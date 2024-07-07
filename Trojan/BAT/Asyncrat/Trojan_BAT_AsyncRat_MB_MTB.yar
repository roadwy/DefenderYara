
rule Trojan_BAT_AsyncRat_MB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 02 6f 90 01 03 0a 17 59 0c 2b 18 00 06 07 93 0d 06 07 06 08 93 9d 06 08 09 9d 00 07 17 58 0b 08 17 59 0c 07 08 fe 04 13 04 11 04 2d 90 00 } //1
		$a_81_1 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_81_2 = {53 65 74 57 69 6e 45 76 65 6e 74 48 6f 6f 6b } //1 SetWinEventHook
		$a_81_3 = {47 65 74 54 61 73 6b 62 61 72 53 74 61 74 65 } //1 GetTaskbarState
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_81_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_7 = {67 65 74 5f 4d 6f 75 73 65 50 6f 73 69 74 69 6f 6e } //1 get_MousePosition
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}