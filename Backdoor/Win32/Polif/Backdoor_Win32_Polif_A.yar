
rule Backdoor_Win32_Polif_A{
	meta:
		description = "Backdoor:Win32/Polif.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 e0 47 c1 e0 51 c1 e0 55 } //01 00 
		$a_01_1 = {bf b0 15 00 00 3b cf 73 02 8b f9 2b cf 0f b6 16 } //01 00 
		$a_01_2 = {c6 44 24 02 4d c6 44 24 03 5a c7 44 24 04 90 00 03 00 } //00 00 
		$a_00_3 = {87 } //10 00 
	condition:
		any of ($a_*)
 
}