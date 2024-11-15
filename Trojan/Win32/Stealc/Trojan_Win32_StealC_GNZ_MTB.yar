
rule Trojan_Win32_StealC_GNZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.GNZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f9 33 c7 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 ?? 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}