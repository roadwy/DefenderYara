
rule Trojan_Win64_Sirefef_AN{
	meta:
		description = "Trojan:Win64/Sirefef.AN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {38 30 30 30 30 30 30 31 2e 40 } //01 00 
		$a_03_1 = {ba 14 00 00 00 33 c9 ff 15 90 01 04 b9 08 00 00 00 48 8b d8 48 85 c0 74 0f 83 60 08 00 c7 00 01 00 00 00 89 48 04 eb 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}