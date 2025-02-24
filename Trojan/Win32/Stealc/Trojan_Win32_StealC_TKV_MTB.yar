
rule Trojan_Win32_StealC_TKV_MTB{
	meta:
		description = "Trojan:Win32/StealC.TKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cb c1 e1 04 03 4d ?? 8d 14 18 33 ca 33 4d f8 05 47 86 c8 61 2b f9 83 6d ?? 01 89 7d ec 89 45 f4 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}