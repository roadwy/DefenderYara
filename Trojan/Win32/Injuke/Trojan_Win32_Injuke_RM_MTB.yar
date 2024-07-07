
rule Trojan_Win32_Injuke_RM_MTB{
	meta:
		description = "Trojan:Win32/Injuke.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 39 4b 57 } //1 This program cannot be run in 9KW
		$a_81_1 = {53 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } //1 SetKeyboardState
		$a_81_2 = {47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } //1 GetKeyboardState
		$a_81_3 = {49 73 52 65 63 74 45 6d 70 74 79 } //1 IsRectEmpty
		$a_81_4 = {6a 31 51 51 6a 6d 53 6a 31 6a 40 } //1 j1QQjmSj1j@
		$a_81_5 = {53 70 65 72 6d 61 74 6f 67 65 6e 65 74 69 63 2e 64 6c 6c } //1 Spermatogenetic.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}