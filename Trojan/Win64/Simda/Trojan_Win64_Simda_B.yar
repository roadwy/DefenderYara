
rule Trojan_Win64_Simda_B{
	meta:
		description = "Trojan:Win64/Simda.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 41 01 32 01 48 83 c1 02 88 02 } //01 00 
		$a_01_1 = {c7 42 2c 57 00 00 00 b8 34 00 00 00 33 ed c6 42 28 f3 } //00 00 
	condition:
		any of ($a_*)
 
}