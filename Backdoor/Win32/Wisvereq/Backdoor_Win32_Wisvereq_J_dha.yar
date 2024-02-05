
rule Backdoor_Win32_Wisvereq_J_dha{
	meta:
		description = "Backdoor:Win32/Wisvereq.J!dha,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 00 } //05 00 
		$a_01_1 = {4e 6f 49 50 0d 0a 00 00 4e 6f 4e 61 6d 65 0d 0a 00 } //01 00 
		$a_01_2 = {49 6d 61 67 69 6e 56 69 65 77 00 } //01 00 
		$a_01_3 = {64 32 68 73 63 48 4e 32 59 79 35 6b 62 47 77 3d 00 } //01 00 
		$a_01_4 = {65 62 76 69 33 30 37 2e 62 61 74 00 } //01 00 
		$a_01_5 = {57 69 6e 32 30 30 30 } //00 00 
	condition:
		any of ($a_*)
 
}