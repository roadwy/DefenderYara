
rule Trojan_Win32_StealC_GNN_MTB{
	meta:
		description = "Trojan:Win32/StealC.GNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 ca 03 c3 33 c1 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 44 24 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}