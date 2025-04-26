
rule Trojan_Win64_ClipBanker_ACA_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.ACA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 55 c0 48 89 45 c8 eb 0b 48 8d 4d 30 e8 ?? ?? ?? ?? eb 38 48 8b 55 c0 48 8b 4d c8 e8 ?? ?? ?? ?? 48 89 55 b0 48 89 45 b8 eb 00 48 8b 55 b0 48 8b 4d b8 31 c0 41 88 c0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}