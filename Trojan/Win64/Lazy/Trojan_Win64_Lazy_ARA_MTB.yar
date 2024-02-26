
rule Trojan_Win64_Lazy_ARA_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {89 c3 80 e3 90 01 01 80 cb 90 01 01 24 90 01 01 30 d8 34 90 01 01 88 05 90 00 } //02 00 
		$a_03_1 = {89 c2 80 e2 90 01 01 80 ca 90 01 01 24 90 01 01 30 d0 34 90 01 01 88 05 90 00 } //03 00 
		$a_01_2 = {74 65 73 74 31 32 33 31 32 33 31 32 33 31 32 33 } //00 00  test123123123123
	condition:
		any of ($a_*)
 
}