
rule Trojan_Win64_MeduzaStealer_AIN_MTB{
	meta:
		description = "Trojan:Win64/MeduzaStealer.AIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 89 c0 31 d2 49 f7 f2 49 8b 03 0f b6 04 10 43 30 04 01 49 83 c0 01 4c 8b 09 48 8b 41 ?? 4c 29 c8 49 39 c0 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}