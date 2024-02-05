
rule Backdoor_Win32_Thoper_A{
	meta:
		description = "Backdoor:Win32/Thoper.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {02 c3 32 04 16 8b 11 88 04 16 a0 90 01 04 0c 04 46 a2 90 01 04 3b 75 0c 0f 8c 90 00 } //01 00 
		$a_01_1 = {77 69 6e 73 76 63 66 73 } //01 00 
		$a_01_2 = {6e 61 74 65 6f 6e 2e 64 75 61 6d 6c 69 76 65 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}