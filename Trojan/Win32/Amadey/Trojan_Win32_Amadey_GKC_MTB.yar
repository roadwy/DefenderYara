
rule Trojan_Win32_Amadey_GKC_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c6 d3 ee 89 44 24 ?? 8b cd 8d 44 24 ?? 89 74 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}