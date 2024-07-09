
rule Trojan_Win64_Emotet_ES_MTB{
	meta:
		description = "Trojan:Win64/Emotet.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cf 2b c8 48 63 c1 42 0f b6 0c ?? 43 32 0c ?? 41 88 ?? ff c7 4d 8d ?? 01 48 83 eb 01 74 09 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}