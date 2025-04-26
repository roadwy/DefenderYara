
rule Trojan_Win32_Vidar_GHL_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 d3 e8 03 45 ?? 89 45 ?? 33 45 ?? 31 45 ?? 8b 45 ?? 29 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? ff 4d ?? 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}