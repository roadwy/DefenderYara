
rule Trojan_Win32_Sirefef_A{
	meta:
		description = "Trojan:Win32/Sirefef.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 37 8b ce 23 f0 83 c7 04 c1 e9 08 3b d6 77 0a } //01 00 
		$a_01_1 = {74 f1 5f 5e ff e0 } //01 00 
		$a_01_2 = {c7 44 24 10 01 00 01 80 ff 74 24 10 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Sirefef_A_2{
	meta:
		description = "Trojan:Win32/Sirefef.A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 37 8b ce 23 f0 83 c7 04 c1 e9 08 3b d6 77 0a } //01 00 
		$a_01_1 = {74 f1 5f 5e ff e0 } //01 00 
		$a_01_2 = {c7 44 24 10 01 00 01 80 ff 74 24 10 } //00 00 
	condition:
		any of ($a_*)
 
}