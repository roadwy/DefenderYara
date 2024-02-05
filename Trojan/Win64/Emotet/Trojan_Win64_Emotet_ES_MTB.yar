
rule Trojan_Win64_Emotet_ES_MTB{
	meta:
		description = "Trojan:Win64/Emotet.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b cf 2b c8 48 63 c1 42 0f b6 0c 90 01 01 43 32 0c 90 01 01 41 88 90 01 01 ff c7 4d 8d 90 01 01 01 48 83 eb 01 74 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}