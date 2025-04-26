
rule Trojan_Win32_Rhadamanthys_GHQ_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.GHQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 d3 ea 8b 4c 24 ?? 8d 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 54 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}