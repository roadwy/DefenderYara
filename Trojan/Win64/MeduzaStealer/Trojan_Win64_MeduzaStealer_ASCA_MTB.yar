
rule Trojan_Win64_MeduzaStealer_ASCA_MTB{
	meta:
		description = "Trojan:Win64/MeduzaStealer.ASCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 05 ?? 00 00 00 43 30 04 26 48 8b 85 ?? 00 00 00 48 ff c0 48 89 85 ?? 00 00 00 49 ff c4 4d 39 fc 74 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}