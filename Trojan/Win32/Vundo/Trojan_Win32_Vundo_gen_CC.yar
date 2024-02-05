
rule Trojan_Win32_Vundo_gen_CC{
	meta:
		description = "Trojan:Win32/Vundo.gen!CC,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 fa 27 86 53 fb 74 44 } //01 00 
		$a_01_1 = {b8 00 10 00 00 50 50 6a 00 ff 15 } //01 00 
		$a_01_2 = {83 e1 1f d3 c6 81 ee 63 1a 00 00 89 34 90 4a } //00 00 
	condition:
		any of ($a_*)
 
}