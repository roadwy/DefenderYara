
rule Backdoor_Win32_Zegost_CP_bit{
	meta:
		description = "Backdoor:Win32/Zegost.CP!bit,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 73 20 4d 65 64 69 61 20 50 6c 61 79 65 72 5c 63 73 72 73 73 2e 65 78 65 } //01 00 
		$a_01_1 = {00 50 6c 75 67 69 6e 4d 65 00 } //01 00 
		$a_01_2 = {00 25 73 5c 25 64 2e 62 61 6b 00 } //00 00 
	condition:
		any of ($a_*)
 
}