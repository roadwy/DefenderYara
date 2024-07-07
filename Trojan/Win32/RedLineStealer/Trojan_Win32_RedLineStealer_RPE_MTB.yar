
rule Trojan_Win32_RedLineStealer_RPE_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b f1 8b ce c1 e1 04 03 4d ec 8b c6 c1 e8 05 03 45 e8 03 de 33 cb 33 c8 8d 45 f4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_RedLineStealer_RPE_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {eb 05 21 bb 90 01 03 50 90 13 e8 17 00 00 00 90 13 90 13 33 c0 eb 02 00 a9 71 64 eb 03 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}