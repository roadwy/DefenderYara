
rule Trojan_Win64_Sirefef_AB{
	meta:
		description = "Trojan:Win64/Sirefef.AB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 31 03 d1 c0 49 83 c3 04 83 c7 ff 75 f2 } //01 00 
		$a_03_1 = {48 89 04 24 49 c7 c0 00 80 00 00 48 33 d2 48 b9 90 01 08 ff 25 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Sirefef_AB_2{
	meta:
		description = "Trojan:Win64/Sirefef.AB,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 31 03 d1 c0 49 83 c3 04 83 c7 ff 75 f2 } //01 00 
		$a_03_1 = {48 89 04 24 49 c7 c0 00 80 00 00 48 33 d2 48 b9 90 01 08 ff 25 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}