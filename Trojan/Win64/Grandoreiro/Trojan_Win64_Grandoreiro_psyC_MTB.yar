
rule Trojan_Win64_Grandoreiro_psyC_MTB{
	meta:
		description = "Trojan:Win64/Grandoreiro.psyC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_03_0 = {8d 95 00 00 ff ff 52 e8 90 01 03 ff 83 c4 04 89 85 f8 ff fe ff 83 bd f8 ff fe ff 00 74 02 eb 0d 68 60 ea 00 00 ff 15 0c 50 40 00 eb d3 b8 01 00 00 00 8b e5 5d c3 ff 25 b8 50 40 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}