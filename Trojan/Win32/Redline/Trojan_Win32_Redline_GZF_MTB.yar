
rule Trojan_Win32_Redline_GZF_MTB{
	meta:
		description = "Trojan:Win32/Redline.GZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d7 8d 04 3b d3 ea 89 45 ?? 8b 45 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 33 c2 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}