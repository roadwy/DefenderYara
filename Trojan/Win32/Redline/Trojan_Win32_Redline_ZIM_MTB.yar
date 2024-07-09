
rule Trojan_Win32_Redline_ZIM_MTB{
	meta:
		description = "Trojan:Win32/Redline.ZIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 55 ?? 89 45 08 8b 45 ?? 01 45 08 8b 45 08 33 45 ?? 33 d2 33 c1 50 89 45 08 } //1
		$a_03_1 = {8b c1 c1 e8 ?? 03 45 ?? 03 f2 33 f0 33 75 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 08 89 75 ?? 8b 45 ?? 29 45 fc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}