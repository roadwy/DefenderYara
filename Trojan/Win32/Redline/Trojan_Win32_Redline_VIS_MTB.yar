
rule Trojan_Win32_Redline_VIS_MTB{
	meta:
		description = "Trojan:Win32/Redline.VIS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 83 3d ?? ?? ?? ?? ?? 0f 85 } //1
		$a_03_1 = {d3 ea 8b 4d ?? 8d 45 ?? 89 5d ?? 89 55 ?? e8 ?? ?? ?? ?? 8b 45 ?? 33 c3 31 45 ?? 89 35 ?? ?? ?? ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 89 45 ?? 81 45 d8 ?? ?? ?? ?? ff 4d ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}