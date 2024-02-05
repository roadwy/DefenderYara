
rule Trojan_Win64_IcedID_DER_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DER!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8a 4c 24 2a 8a 54 24 29 89 d3 44 30 fb 44 20 d3 44 20 da 08 da 89 cb 44 30 fb 44 20 d3 44 20 d9 08 d9 30 d1 88 4c 24 29 } //00 00 
	condition:
		any of ($a_*)
 
}