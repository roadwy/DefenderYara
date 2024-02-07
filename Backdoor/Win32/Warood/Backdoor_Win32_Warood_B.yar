
rule Backdoor_Win32_Warood_B{
	meta:
		description = "Backdoor:Win32/Warood.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 14 31 8a 18 d2 e2 0a da 41 83 f9 08 88 18 7c ef } //01 00 
		$a_01_1 = {8a 14 01 8a 18 32 da 88 18 40 4e 75 f3 } //01 00 
		$a_01_2 = {5b 2d 5d 4e 54 54 69 6d 65 } //00 00  [-]NTTime
	condition:
		any of ($a_*)
 
}