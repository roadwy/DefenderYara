
rule Trojan_Win64_StealC_NS_MTB{
	meta:
		description = "Trojan:Win64/StealC.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {7d 20 48 63 44 24 90 01 01 48 8b 4c 24 58 8b 04 01 03 44 24 90 01 01 48 63 4c 24 90 01 01 48 8b 54 24 30 89 04 90 00 } //03 00 
		$a_03_1 = {8b 44 24 20 83 c0 90 01 01 89 44 24 20 81 7c 24 20 00 60 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}