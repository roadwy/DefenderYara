
rule Trojan_Win32_Redline_TIY_MTB{
	meta:
		description = "Trojan:Win32/Redline.TIY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 07 c1 e8 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 c1 31 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 75 } //1
		$a_03_1 = {6a 00 ff 15 ?? ?? ?? ?? 31 5c 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 81 c7 ?? ?? ?? ?? ff 4c 24 ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}