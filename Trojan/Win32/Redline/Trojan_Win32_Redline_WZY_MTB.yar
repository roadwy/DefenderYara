
rule Trojan_Win32_Redline_WZY_MTB{
	meta:
		description = "Trojan:Win32/Redline.WZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 ?? 03 45 ?? 03 fe 33 f8 31 7d ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 29 45 ?? 68 ?? ?? ?? ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? ff 4d ?? 8b 45 ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}