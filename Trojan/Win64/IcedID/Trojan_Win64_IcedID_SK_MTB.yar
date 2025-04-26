
rule Trojan_Win64_IcedID_SK_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c1 48 63 0c 24 eb ?? 8b 4c 24 ?? 33 c8 eb ?? 89 44 24 } //1
		$a_03_1 = {c3 99 f7 7c 24 ?? eb ?? 8b c2 48 ?? eb ?? 48 ?? ?? ?? c7 04 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}