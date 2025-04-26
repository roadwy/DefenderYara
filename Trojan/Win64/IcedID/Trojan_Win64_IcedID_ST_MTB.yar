
rule Trojan_Win64_IcedID_ST_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 ff c0 eb ?? 99 f7 7c 24 ?? eb ?? 48 83 ec ?? c7 04 24 } //1
		$a_03_1 = {0f b6 04 01 eb ?? 8b 4c 24 ?? 33 c8 eb ?? 8b c2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}