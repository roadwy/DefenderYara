
rule Backdoor_Win32_Polnur_C{
	meta:
		description = "Backdoor:Win32/Polnur.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {ff 74 24 10 8d 46 01 50 c6 06 7c e8 } //02 00 
		$a_01_1 = {3b fb 76 09 80 34 33 09 43 3b df 72 f7 } //01 00 
		$a_01_2 = {6a 01 56 c6 06 81 e8 } //01 00 
		$a_01_3 = {69 c0 0c 01 00 00 8d 44 30 14 50 } //02 00 
		$a_01_4 = {c6 45 f0 7b c6 45 f1 01 } //00 00 
	condition:
		any of ($a_*)
 
}