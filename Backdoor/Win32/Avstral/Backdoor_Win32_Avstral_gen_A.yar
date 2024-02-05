
rule Backdoor_Win32_Avstral_gen_A{
	meta:
		description = "Backdoor:Win32/Avstral.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {68 ff 00 00 00 68 90 01 04 e8 90 01 04 68 90 01 04 68 90 01 04 e8 90 01 04 6a 00 6a 20 6a 04 6a 00 6a 01 68 00 00 00 c0 68 90 01 04 e8 90 01 04 a3 90 01 04 6a 02 6a 00 6a 00 ff 35 90 01 04 e8 90 01 04 ff 75 08 e8 90 00 } //0a 00 
		$a_00_1 = {5c 57 69 6e 69 2e 69 6e 69 } //0a 00 
		$a_00_2 = {49 6e 73 74 61 6c 6c 48 6f 6f 6b } //01 00 
		$a_00_3 = {48 45 4c 4f 20 6d 61 69 6c 2e 72 75 } //00 00 
	condition:
		any of ($a_*)
 
}