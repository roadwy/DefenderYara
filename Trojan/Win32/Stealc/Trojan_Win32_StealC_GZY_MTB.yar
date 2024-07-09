
rule Trojan_Win32_StealC_GZY_MTB{
	meta:
		description = "Trojan:Win32/StealC.GZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 33 89 45 ?? 8b 45 ?? c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 83 65 ?? ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 33 45 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}