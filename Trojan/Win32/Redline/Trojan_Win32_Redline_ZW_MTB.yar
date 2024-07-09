
rule Trojan_Win32_Redline_ZW_MTB{
	meta:
		description = "Trojan:Win32/Redline.ZW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d d4 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 e0 8d 45 e0 e8 ?? ?? ?? ?? 8b 45 d0 31 45 f8 8b 45 f8 31 45 e0 83 3d 9c 61 c4 02 1f 0f 85 } //1
		$a_03_1 = {d3 ea 8b 4d c4 8d 45 e0 89 55 e0 e8 ?? ?? ?? ?? 8b 45 e0 33 c3 31 45 f8 89 35 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}