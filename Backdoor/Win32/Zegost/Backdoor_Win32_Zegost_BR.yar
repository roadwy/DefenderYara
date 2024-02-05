
rule Backdoor_Win32_Zegost_BR{
	meta:
		description = "Backdoor:Win32/Zegost.BR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 ff d6 53 ff d6 8d 87 80 00 00 00 68 90 01 04 50 ff 15 90 00 } //01 00 
		$a_01_1 = {57 ff d6 8a 03 57 32 45 13 02 45 13 88 03 43 ff d6 } //01 00 
		$a_01_2 = {6a 04 56 ff 77 50 ff 77 34 ff d3 89 45 fc 90 } //00 00 
	condition:
		any of ($a_*)
 
}