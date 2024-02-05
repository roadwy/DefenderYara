
rule Backdoor_Win32_Fludupot_A{
	meta:
		description = "Backdoor:Win32/Fludupot.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4a f5 04 00 00 00 c2 f5 00 00 00 00 c7 1c } //01 00 
		$a_03_1 = {53 65 6e 64 46 6c 6f 6f 64 90 02 04 53 74 6f 70 46 6c 6f 6f 64 90 02 04 53 74 61 72 74 54 43 50 90 02 04 53 74 6f 70 54 43 50 90 02 04 53 74 61 72 74 44 6f 53 90 02 04 53 74 6f 70 44 6f 53 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}