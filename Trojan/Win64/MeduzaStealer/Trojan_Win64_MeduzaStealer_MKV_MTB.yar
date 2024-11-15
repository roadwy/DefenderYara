
rule Trojan_Win64_MeduzaStealer_MKV_MTB{
	meta:
		description = "Trojan:Win64/MeduzaStealer.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b c7 48 89 45 f0 0f b6 44 05 b0 41 30 04 1e 48 8b 45 f0 48 ff c0 48 89 45 ?? 48 8b c8 48 ff c3 48 3b df 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}