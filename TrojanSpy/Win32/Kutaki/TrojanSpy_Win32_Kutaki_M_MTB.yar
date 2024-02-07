
rule TrojanSpy_Win32_Kutaki_M_MTB{
	meta:
		description = "TrojanSpy:Win32/Kutaki.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {44 54 50 69 63 6b 65 72 } //03 00  DTPicker
		$a_81_1 = {53 48 44 6f 63 56 77 43 74 6c 2e 57 65 62 42 72 6f 77 73 65 72 } //03 00  SHDocVwCtl.WebBrowser
		$a_81_2 = {53 6c 65 65 70 } //03 00  Sleep
		$a_81_3 = {65 79 65 73 68 65 72 65 } //03 00  eyeshere
		$a_81_4 = {4c 6f 67 67 65 72 } //03 00  Logger
		$a_81_5 = {73 68 65 6c 6c 65 64 } //03 00  shelled
		$a_81_6 = {6d 75 66 75 63 6b 72 } //00 00  mufuckr
	condition:
		any of ($a_*)
 
}