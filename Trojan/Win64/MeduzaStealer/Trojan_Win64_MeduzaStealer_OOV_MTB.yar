
rule Trojan_Win64_MeduzaStealer_OOV_MTB{
	meta:
		description = "Trojan:Win64/MeduzaStealer.OOV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 c1 e8 10 88 85 4e 04 00 00 c1 e9 18 88 8d 4f 04 00 00 48 c7 85 ?? ?? ?? ?? 00 00 00 00 31 c0 4c 8b a5 10 09 00 00 48 8b b5 18 09 00 00 48 8b 8d 08 09 00 00 0f b6 84 05 10 04 00 00 30 04 0e 48 8b 85 ?? ?? ?? ?? 48 ff c0 48 89 85 ?? ?? ?? ?? 48 ff c1 4c 39 e1 0f 84 ?? ?? ?? ?? 48 83 f8 40 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}