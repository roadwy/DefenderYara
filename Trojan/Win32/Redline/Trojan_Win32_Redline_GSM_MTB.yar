
rule Trojan_Win32_Redline_GSM_MTB{
	meta:
		description = "Trojan:Win32/Redline.GSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 33 7d ?? 31 7d ?? 83 3d ?? ?? ?? ?? ?? 75 } //1
		$a_03_1 = {d3 e0 03 45 ?? 33 45 ?? 33 c2 89 45 ?? 8b 45 ?? 29 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? ff 4d ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}