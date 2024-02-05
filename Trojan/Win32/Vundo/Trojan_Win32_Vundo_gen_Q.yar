
rule Trojan_Win32_Vundo_gen_Q{
	meta:
		description = "Trojan:Win32/Vundo.gen!Q,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 7a 73 05 90 09 03 00 90 03 03 04 c7 04 24 90 01 02 68 90 00 } //01 00 
		$a_03_1 = {80 93 a5 5f 90 09 03 00 90 03 03 04 c7 04 24 90 01 02 68 90 00 } //01 00 
		$a_03_2 = {f4 57 cf 2b 90 09 03 00 90 03 03 04 c7 04 24 90 01 02 68 90 00 } //01 00 
		$a_03_3 = {92 f5 ee 39 90 09 03 00 90 03 03 04 c7 04 24 90 01 02 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}