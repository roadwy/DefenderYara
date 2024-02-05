
rule Backdoor_Win32_Darkshell_A{
	meta:
		description = "Backdoor:Win32/Darkshell.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {4b e1 22 00 0f 85 90 01 02 00 00 83 65 90 01 01 00 6a 04 6a 04 90 00 } //01 00 
		$a_03_1 = {83 4d fc ff 8b 1b 90 02 03 a1 90 01 04 39 58 90 01 01 77 90 01 01 c7 45 90 01 01 0d 00 00 c0 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}