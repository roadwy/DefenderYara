
rule Backdoor_Win32_Rashster_gen_A{
	meta:
		description = "Backdoor:Win32/Rashster.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {34 d7 88 04 11 41 3b ce 7c ef } //01 00 
		$a_01_1 = {68 65 61 72 74 62 65 61 74 00 } //01 00  敨牡扴慥t
		$a_01_2 = {63 6d 64 73 68 65 6c 6c 00 } //01 00 
		$a_01_3 = {25 73 35 63 35 33 65 73 2e 69 6e 69 00 } //01 00 
		$a_01_4 = {61 50 33 6a 33 00 } //00 00  偡樳3
	condition:
		any of ($a_*)
 
}