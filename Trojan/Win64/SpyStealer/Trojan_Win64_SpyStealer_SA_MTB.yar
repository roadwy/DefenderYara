
rule Trojan_Win64_SpyStealer_SA_MTB{
	meta:
		description = "Trojan:Win64/SpyStealer.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 ?? 0f be 00 85 c0 74 2b 48 8b 44 24 ?? 0f b6 00 8b 0c 24 33 c8 8b c1 89 04 24 48 8b 44 24 ?? 48 ff c0 48 89 44 24 ?? 69 04 24 ?? ?? ?? ?? 89 04 24 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}