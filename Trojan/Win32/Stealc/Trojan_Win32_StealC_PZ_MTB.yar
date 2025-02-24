
rule Trojan_Win32_StealC_PZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.PZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 c1 ea ?? 89 55 ?? 8b 45 ?? 01 45 ?? 8b f3 c1 e6 ?? 03 75 ?? 8d 04 1f 33 f0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}