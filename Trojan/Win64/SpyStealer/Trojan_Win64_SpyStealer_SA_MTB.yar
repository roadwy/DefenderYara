
rule Trojan_Win64_SpyStealer_SA_MTB{
	meta:
		description = "Trojan:Win64/SpyStealer.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 90 01 01 0f be 00 85 c0 74 2b 48 8b 44 24 90 01 01 0f b6 00 8b 0c 24 33 c8 8b c1 89 04 24 48 8b 44 24 90 01 01 48 ff c0 48 89 44 24 90 01 01 69 04 24 90 01 04 89 04 24 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}