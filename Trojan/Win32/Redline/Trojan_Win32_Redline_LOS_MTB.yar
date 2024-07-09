
rule Trojan_Win32_Redline_LOS_MTB{
	meta:
		description = "Trojan:Win32/Redline.LOS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d e8 01 4d f8 33 c6 50 8d 45 f8 50 89 3d ?? ?? ?? ?? e8 } //1
		$a_03_1 = {c1 e8 05 03 45 e4 03 f1 33 f0 33 75 0c c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 75 f8 8b 45 f8 29 45 fc 68 ?? ?? ?? ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? ff 4d ec 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}