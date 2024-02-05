
rule Backdoor_Win32_Escad_M_dha{
	meta:
		description = "Backdoor:Win32/Escad.M!dha,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 64 2e 65 25 73 63 20 6e 25 73 73 68 25 73 72 65 77 61 25 73 20 61 64 25 73 20 70 6f 25 73 6f 70 25 73 69 6e 67 20 54 25 73 20 25 64 20 22 25 73 22 } //01 00 
		$a_01_1 = {2a 00 2a 00 2a 00 2a 00 2a 00 5b 00 4c 00 69 00 73 00 74 00 65 00 6e 00 20 00 50 00 6f 00 72 00 74 00 20 00 25 00 64 00 5d 00 20 00 2d 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Escad_M_dha_2{
	meta:
		description = "Backdoor:Win32/Escad.M!dha,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 64 2e 65 25 73 63 20 6e 25 73 73 68 25 73 72 65 77 61 25 73 20 61 64 25 73 20 70 6f 25 73 6f 70 25 73 69 6e 67 20 54 25 73 20 25 64 20 22 25 73 22 } //01 00 
		$a_01_1 = {2a 00 2a 00 2a 00 2a 00 2a 00 5b 00 4c 00 69 00 73 00 74 00 65 00 6e 00 20 00 50 00 6f 00 72 00 74 00 20 00 25 00 64 00 5d 00 20 00 2d 00 } //00 00 
		$a_01_2 = {00 5d } //04 00 
	condition:
		any of ($a_*)
 
}