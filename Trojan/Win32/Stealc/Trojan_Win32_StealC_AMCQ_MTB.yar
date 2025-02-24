
rule Trojan_Win32_StealC_AMCQ_MTB{
	meta:
		description = "Trojan:Win32/StealC.AMCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 33 94 86 ?? ?? ?? ?? 0f b6 c3 8b 5d ?? 03 94 86 ?? ?? ?? ?? 8b 45 ?? 31 14 c8 83 6d ?? 01 8b 04 c8 8b 14 cb 89 04 cb 89 54 cb ?? 75 ?? 8b c8 8b 45 ?? 89 14 c3 89 4c c3 ?? 8b 46 ?? 33 c1 8b 4d ?? 89 44 cb ?? 8b 06 31 04 cb 41 8d 46 ?? 89 4d } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}