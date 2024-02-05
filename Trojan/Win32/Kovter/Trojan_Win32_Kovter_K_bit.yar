
rule Trojan_Win32_Kovter_K_bit{
	meta:
		description = "Trojan:Win32/Kovter.K!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 29 00 53 79 73 74 65 6d 2e 64 6c 6c 00 03 95 80 5c 53 79 73 74 65 6d 2e 64 6c 6c } //01 00 
		$a_01_1 = {73 70 6f 72 74 73 77 6f 6d 61 6e 2e 64 6c 6c 00 43 6f 6e 73 63 72 69 70 74 50 72 6f 74 6f 7a 6f 61 6e 42 65 64 66 65 6c 6c 6f 77 00 73 70 6f 72 74 73 77 6f 6d 61 6e 3a 3a 43 65 6e 74 6f } //01 00 
		$a_01_2 = {00 43 72 61 76 61 74 57 61 72 72 61 67 61 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}