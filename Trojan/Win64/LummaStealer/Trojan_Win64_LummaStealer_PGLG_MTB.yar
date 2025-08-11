
rule Trojan_Win64_LummaStealer_PGLG_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.PGLG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c1 0f b6 c1 48 8b 4d ?? 8a 04 01 48 63 4d ?? 41 30 04 ?? 8b 45 ?? 83 c0 ?? 89 45 ?? 8b 05 ?? ?? ?? ?? 8d 48 ff 0f af c8 f6 c1 01 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}