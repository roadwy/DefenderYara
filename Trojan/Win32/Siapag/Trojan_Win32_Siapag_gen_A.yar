
rule Trojan_Win32_Siapag_gen_A{
	meta:
		description = "Trojan:Win32/Siapag.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 54 24 04 b9 90 01 02 f9 90 01 01 8a 02 84 c0 74 0d 34 c5 88 01 8a 42 01 41 42 84 c0 75 f3 c6 01 00 b8 90 01 02 f9 90 01 01 c3 90 00 } //01 00 
		$a_00_1 = {63 6a 77 65 77 6b 6c 77 72 65 6f } //01 00 
		$a_00_2 = {49 73 47 61 6d 65 50 6c 61 79 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}