
rule PWS_Win32_Eldeyike_A{
	meta:
		description = "PWS:Win32/Eldeyike.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 6c 69 6e 6b 69 6e 73 69 64 65 2e 63 6f 2e 6b 72 } //01 00 
		$a_01_1 = {6c 69 6e 6b 69 6e 73 69 64 65 76 6b 00 } //01 00 
		$a_01_2 = {6c 69 6e 6b 69 6e 73 69 64 65 5f 63 6f 6e 69 66 67 2e 69 6e 69 00 } //01 00 
		$a_01_3 = {6c 69 6e 6b 69 6e 73 69 64 65 73 5f 73 70 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}