
rule Trojan_Win64_Emotet_EF_MTB{
	meta:
		description = "Trojan:Win64/Emotet.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 c2 89 c8 29 d0 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Emotet_EF_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 d0 29 c1 89 ca 48 63 c2 4c 01 d0 0f b6 00 44 31 c8 41 88 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}