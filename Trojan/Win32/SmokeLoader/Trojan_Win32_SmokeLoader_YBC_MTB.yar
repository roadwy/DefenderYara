
rule Trojan_Win32_SmokeLoader_YBC_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.YBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 05 03 44 24 20 03 cd 33 c1 8d 0c 33 33 c1 2b f8 8b d7 c1 e2 04 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 } //1
		$a_03_1 = {33 d3 33 c2 89 44 24 10 2b f0 8d 44 24 18 e8 ?? ?? ?? ?? ff 4c 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}