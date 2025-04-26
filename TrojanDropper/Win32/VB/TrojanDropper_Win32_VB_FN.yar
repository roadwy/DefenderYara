
rule TrojanDropper_Win32_VB_FN{
	meta:
		description = "TrojanDropper:Win32/VB.FN,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {43 00 3a 00 5c 00 77 00 69 00 6e 00 61 00 70 00 70 00 2e 00 76 00 62 00 70 00 } //1 C:\winapp.vbp
		$a_00_1 = {55 00 41 00 43 00 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 4e 00 6f 00 74 00 69 00 66 00 79 00 } //1 UACDisableNotify
		$a_01_2 = {63 72 70 74 73 74 72 } //1 crptstr
		$a_01_3 = {49 4e 50 55 54 53 54 52 49 4e 47 } //1 INPUTSTRING
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}