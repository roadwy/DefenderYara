
rule Trojan_Win32_Simda_gen_B{
	meta:
		description = "Trojan:Win32/Simda.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {80 3e 21 89 74 24 } //02 00 
		$a_03_1 = {76 0b 80 34 30 90 01 01 83 c0 01 3b c7 72 f5 90 00 } //01 00 
		$a_01_2 = {2f 6b 6e 6f 63 6b 2e 70 68 70 3f } //01 00 
		$a_01_3 = {21 63 6f 6e 66 69 67 } //00 00 
	condition:
		any of ($a_*)
 
}