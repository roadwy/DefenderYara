
rule Trojan_Win32_Pakes_gen_I{
	meta:
		description = "Trojan:Win32/Pakes.gen!I,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 00 81 c2 00 0e 00 00 6a 00 c1 e2 04 52 56 ff } //01 00 
		$a_03_1 = {8a 4c 04 08 80 f1 90 01 01 88 4c 04 08 40 83 f8 10 7c ef 90 00 } //05 00 
		$a_03_2 = {8b 54 24 14 8b ce 8d 44 1a c1 50 8d 46 04 50 e8 90 01 01 00 00 00 83 c3 40 83 c5 40 3b df 72 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}