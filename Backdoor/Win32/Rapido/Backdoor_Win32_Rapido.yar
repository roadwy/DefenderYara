
rule Backdoor_Win32_Rapido{
	meta:
		description = "Backdoor:Win32/Rapido,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {47 72 61 63 69 61 73 20 70 6f 72 20 75 74 69 6c 69 7a 61 72 20 6c 6f 73 20 73 65 72 76 69 63 69 6f 73 20 64 65 20 61 63 63 65 73 6f } //03 00 
		$a_01_1 = {2e 61 63 63 65 73 6f 72 61 70 69 64 6f 2e 63 6f 6d } //02 00 
		$a_01_2 = {20 70 6f 72 20 6d 69 6e 75 74 6f 2e } //02 00 
		$a_01_3 = {54 69 65 6d 70 6f 20 61 70 72 6f 78 2e 20 72 65 73 74 61 6e 74 65 3a 20 25 64 6d 20 25 64 73 } //00 00 
	condition:
		any of ($a_*)
 
}