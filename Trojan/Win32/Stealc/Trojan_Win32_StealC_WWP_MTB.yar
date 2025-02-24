
rule Trojan_Win32_StealC_WWP_MTB{
	meta:
		description = "Trojan:Win32/StealC.WWP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e8 05 89 45 ?? 8b 45 e8 01 45 ?? 8b cb c1 e1 04 03 4d e4 8d 14 1f 33 ca 33 4d ?? 89 4d ec 8b 45 ?? 29 45 f8 81 c7 47 86 c8 61 83 6d f0 01 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}