
rule Backdoor_Win32_Wisvereq_G{
	meta:
		description = "Backdoor:Win32/Wisvereq.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 00 } //01 00 
		$a_01_1 = {75 70 66 69 6c 65 00 00 63 6d 64 2e 65 78 65 00 } //01 00 
		$a_03_2 = {61 62 00 00 25 90 02 02 64 90 02 04 6c 6f 61 64 66 69 6c 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}