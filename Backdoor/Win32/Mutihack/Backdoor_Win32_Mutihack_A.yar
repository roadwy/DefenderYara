
rule Backdoor_Win32_Mutihack_A{
	meta:
		description = "Backdoor:Win32/Mutihack.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 04 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 5c 4d 75 74 69 25 64 48 61 63 6b } //01 00 
		$a_01_1 = {6d 75 74 69 68 61 63 6b 2e 64 6c 6c } //01 00 
		$a_01_2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 20 53 74 61 72 74 75 70 20 25 73 } //02 00 
		$a_01_3 = {62 62 73 2e 4d 75 74 69 48 61 63 6b 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}