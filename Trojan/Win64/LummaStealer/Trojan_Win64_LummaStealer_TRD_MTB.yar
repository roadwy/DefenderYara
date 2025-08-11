
rule Trojan_Win64_LummaStealer_TRD_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.TRD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c1 0f b6 c1 8a 84 04 ?? 01 00 00 48 63 8c 24 88 00 00 00 41 30 04 0e 8b 84 24 88 00 00 00 83 c0 01 89 44 24 74 8b 05 ?? ?? ?? ?? 8d 48 ff 0f af c8 f6 c1 01 b8 6f d3 a3 d3 b9 e9 b6 aa 85 e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}