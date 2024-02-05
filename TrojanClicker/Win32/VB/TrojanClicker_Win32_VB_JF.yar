
rule TrojanClicker_Win32_VB_JF{
	meta:
		description = "TrojanClicker:Win32/VB.JF,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 63 00 6f 00 6d 00 2f 00 61 00 64 00 2f 00 74 00 35 00 2e 00 61 00 73 00 70 00 } //01 00 
		$a_01_1 = {31 00 2e 00 76 00 62 00 70 00 } //01 00 
		$a_01_2 = {5c 00 63 00 73 00 68 00 2e 00 64 00 6c 00 6c 00 } //01 00 
		$a_01_3 = {53 65 74 42 72 6f 77 73 65 72 4d 75 74 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}