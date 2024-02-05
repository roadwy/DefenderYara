
rule Backdoor_Win32_Quisset_A{
	meta:
		description = "Backdoor:Win32/Quisset.A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {05 80 d4 7d ee 6a 00 83 d1 02 68 80 96 98 00 51 50 e8 } //02 00 
		$a_00_1 = {2e 70 68 70 3f 6d 61 63 3d } //01 00 
		$a_00_2 = {2e 64 65 6c 65 74 65 64 } //01 00 
		$a_00_3 = {64 65 6c 6f 6e 6c 79 } //01 00 
		$a_00_4 = {73 74 61 72 74 75 72 6c } //00 00 
	condition:
		any of ($a_*)
 
}