
rule Backdoor_Win32_Coroxy_B{
	meta:
		description = "Backdoor:Win32/Coroxy.B,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {68 7f 66 04 40 ff 75 fc e8 } //05 00 
		$a_03_1 = {b8 fc fd fe ff b9 40 00 00 00 90 01 07 2d 04 04 04 04 90 00 } //05 00 
		$a_00_2 = {2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 65 70 20 62 79 70 61 73 73 } //01 00 
		$a_00_3 = {48 4f 53 54 31 3a 31 34 39 2e 32 38 2e 31 30 2e 32 35 30 } //01 00 
		$a_00_4 = {48 4f 53 54 31 3a 32 33 2e 31 33 33 2e 36 2e 33 39 } //00 00 
	condition:
		any of ($a_*)
 
}