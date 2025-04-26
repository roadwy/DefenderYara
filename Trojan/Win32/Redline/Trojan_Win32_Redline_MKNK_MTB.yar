
rule Trojan_Win32_Redline_MKNK_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 31 4c 24 ?? 83 3d } //1
		$a_03_1 = {d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8b 44 24 ?? 33 c1 2b f0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}