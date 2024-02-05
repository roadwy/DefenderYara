
rule Trojan_Win64_Fabookie_DAC_MTB{
	meta:
		description = "Trojan:Win64/Fabookie.DAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {ff d0 49 89 c5 4c 89 e9 48 89 f2 41 c7 c0 80 84 1e 00 4c 8d 8c 24 bc 00 00 00 48 8b 84 24 98 00 00 00 ff d0 81 bc 24 bc 00 00 00 2c 9e 15 00 73 0f 48 89 f9 ff d3 4c 89 e9 ff d3 e9 } //00 00 
	condition:
		any of ($a_*)
 
}