
rule Trojan_Win32_Vundo_gen_BV{
	meta:
		description = "Trojan:Win32/Vundo.gen!BV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {e8 02 08 00 00 38 5d d3 0f 84 ce 00 00 00 68 90 01 04 8d 45 d4 e8 13 04 00 00 be 90 01 04 56 90 00 } //01 00 
		$a_00_1 = {38 00 33 00 2e 00 31 00 34 00 39 00 2e 00 31 00 31 00 35 00 2e 00 31 00 35 00 37 00 } //01 00  83.149.115.157
		$a_01_2 = {44 4e 53 43 68 61 6e 67 65 72 57 69 6e 2e 64 6c 6c 00 72 } //00 00 
	condition:
		any of ($a_*)
 
}