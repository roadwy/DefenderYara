
rule Trojan_Win64_MeduzaStealer_AIDA_MTB{
	meta:
		description = "Trojan:Win64/MeduzaStealer.AIDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b d7 48 89 55 ?? 0f b6 44 15 ?? 41 30 04 1e 48 8b 55 ?? 48 ff c2 48 89 55 ?? 48 8b c2 48 ff c3 48 3b df 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}