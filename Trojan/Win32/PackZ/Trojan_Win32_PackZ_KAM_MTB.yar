
rule Trojan_Win32_PackZ_KAM_MTB{
	meta:
		description = "Trojan:Win32/PackZ.KAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 3a 81 c0 90 01 04 bb 90 01 04 01 c1 81 e7 90 01 04 48 b9 90 01 04 31 3e 29 c8 f7 d1 81 c6 90 01 04 81 c3 90 01 04 89 cb b9 90 01 04 81 c2 90 01 04 f7 d3 b8 90 01 04 09 c0 81 fe 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}