
rule Trojan_Win32_Vundo_gen_N{
	meta:
		description = "Trojan:Win32/Vundo.gen!N,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {1a 9d d5 71 90 09 03 00 90 03 03 04 c7 04 24 90 01 02 68 90 00 } //01 00 
		$a_03_1 = {16 85 d9 5d 90 09 03 00 90 03 03 04 c7 04 24 90 01 02 68 90 00 } //01 00 
		$a_03_2 = {c0 41 6a 4e 90 09 03 00 90 03 03 04 c7 04 24 90 01 02 68 90 00 } //01 00 
		$a_03_3 = {b4 e4 39 28 90 09 03 00 90 03 03 04 c7 04 24 90 01 02 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}