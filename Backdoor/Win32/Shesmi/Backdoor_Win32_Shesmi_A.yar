
rule Backdoor_Win32_Shesmi_A{
	meta:
		description = "Backdoor:Win32/Shesmi.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {73 68 65 73 68 7a 6d 79 } //05 00 
		$a_01_1 = {32 30 63 6e 46 54 50 } //01 00 
		$a_01_2 = {00 32 33 30 20 } //01 00 
		$a_01_3 = {00 33 33 31 20 } //01 00 
		$a_01_4 = {00 32 30 30 20 } //00 00 
		$a_00_5 = {5d 04 00 00 81 64 } //03 80 
	condition:
		any of ($a_*)
 
}