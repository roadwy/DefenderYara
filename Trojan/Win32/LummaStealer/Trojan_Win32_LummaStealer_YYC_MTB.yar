
rule Trojan_Win32_LummaStealer_YYC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.YYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 c1 e2 04 03 55 ?? 33 55 f8 33 d1 2b fa 89 7d ec 8b 45 d4 29 45 f4 83 6d ?? 01 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}