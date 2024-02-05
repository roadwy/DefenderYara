
rule Backdoor_Win32_Nioupale_A{
	meta:
		description = "Backdoor:Win32/Nioupale.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 73 68 6f 73 74 2e 65 78 65 } //01 00 
		$a_01_1 = {6d 73 69 64 2e 64 61 74 00 } //01 00 
		$a_01_2 = {cc 38 38 34 e2 f7 f7 } //01 00 
		$a_01_3 = {f7 c5 c8 c8 3a f6 cf cd ce } //01 00 
		$a_01_4 = {2f 61 64 64 72 2e 67 69 66 } //01 00 
		$a_03_5 = {25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 53 79 73 74 65 6d 90 01 04 5c 4c 69 62 72 61 72 79 90 01 04 5c 53 79 73 74 65 6d 00 43 6f 6d 6d 6f 6e 46 69 6c 65 73 44 69 72 90 00 } //01 00 
		$a_01_6 = {74 65 78 74 3d 49 44 3d 00 } //00 00 
		$a_00_7 = {80 10 00 } //00 de 
	condition:
		any of ($a_*)
 
}