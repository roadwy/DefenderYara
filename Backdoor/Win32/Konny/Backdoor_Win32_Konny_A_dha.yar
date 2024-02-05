
rule Backdoor_Win32_Konny_A_dha{
	meta:
		description = "Backdoor:Win32/Konny.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 25 73 5c 73 6f 6c 68 65 6c 70 2e 6f 63 78 00 } //01 00 
		$a_01_1 = {00 69 64 3d 25 73 26 70 61 73 73 77 64 3d 25 73 00 } //00 00 
		$a_00_2 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}