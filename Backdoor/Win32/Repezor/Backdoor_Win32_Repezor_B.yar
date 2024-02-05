
rule Backdoor_Win32_Repezor_B{
	meta:
		description = "Backdoor:Win32/Repezor.B,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {30 3a 5c 73 74 6f 72 61 67 65 5c 63 6f 6e 66 69 67 00 } //01 00 
		$a_01_1 = {62 63 5f 70 6c 75 67 00 } //01 00 
		$a_03_2 = {01 05 00 00 74 90 01 01 81 7d 90 01 01 02 05 00 00 74 90 01 01 eb 90 01 01 81 7d 90 01 01 01 06 00 00 74 90 01 01 81 7d 90 01 01 02 06 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}