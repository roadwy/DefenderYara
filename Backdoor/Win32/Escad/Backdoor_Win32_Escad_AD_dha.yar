
rule Backdoor_Win32_Escad_AD_dha{
	meta:
		description = "Backdoor:Win32/Escad.AD!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 5c 70 6d 2a 2e 65 78 65 00 } //01 00 
		$a_01_1 = {69 67 66 78 63 6f 6e 66 2e 65 78 65 00 } //01 00 
		$a_01_2 = {77 69 6e 6d 73 6e 33 32 2e 00 } //01 00 
		$a_01_3 = {25 73 64 2e 65 25 73 63 20 25 73 00 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}