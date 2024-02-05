
rule Backdoor_Win32_Rifdoor_B_bit{
	meta:
		description = "Backdoor:Win32/Rifdoor.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c8 80 30 0f 41 8b c1 38 19 75 f6 } //01 00 
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 41 68 6e 4c 61 62 5c 41 68 6e 53 76 63 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}