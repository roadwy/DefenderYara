
rule Trojan_Win32_Redline_ZYZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.ZYZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 03 4d ?? 8d 45 ?? 33 4d ?? 33 d2 33 4d ?? 89 15 ?? ?? ?? ?? 51 50 89 4d ?? e8 } //1
		$a_03_1 = {c1 e8 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 08 8b 45 ?? 01 45 ?? 03 f3 33 75 ?? 8d 45 ?? 33 75 ?? 56 50 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}