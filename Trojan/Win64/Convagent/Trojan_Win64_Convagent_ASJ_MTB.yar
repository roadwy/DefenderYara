
rule Trojan_Win64_Convagent_ASJ_MTB{
	meta:
		description = "Trojan:Win64/Convagent.ASJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 08 03 14 24 33 54 24 04 89 54 24 ?? 8b 54 24 1c e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}