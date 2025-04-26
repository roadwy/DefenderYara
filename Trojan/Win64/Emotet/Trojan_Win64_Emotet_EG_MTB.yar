
rule Trojan_Win64_Emotet_EG_MTB{
	meta:
		description = "Trojan:Win64/Emotet.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 31 d2 45 88 d3 48 8b 8d ?? 0b 00 00 4c 63 4d ?? 46 88 1c 09 8b 45 ?? 83 c0 01 89 45 ?? e9 ?? ff ff ff } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}