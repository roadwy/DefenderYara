
rule Trojan_Win64_MeduzaStealer_MRJ_MTB{
	meta:
		description = "Trojan:Win64/MeduzaStealer.MRJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c8 31 d2 49 f7 f0 48 8b 44 24 ?? 0f b6 04 10 30 04 0b 48 83 c1 01 48 8b 1e 48 8b 46 ?? 48 29 d8 48 39 c1 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}