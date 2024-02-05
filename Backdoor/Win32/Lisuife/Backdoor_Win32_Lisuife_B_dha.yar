
rule Backdoor_Win32_Lisuife_B_dha{
	meta:
		description = "Backdoor:Win32/Lisuife.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 37 36 2e 33 31 2e 31 31 32 2e 31 30 } //01 00 
		$a_01_1 = {69 73 20 79 6f 75 20 6c 69 76 65 3f } //01 00 
		$a_01_2 = {69 60 6d 20 77 61 69 74 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}