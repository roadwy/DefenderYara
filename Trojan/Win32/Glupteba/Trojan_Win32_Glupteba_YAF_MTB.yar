
rule Trojan_Win32_Glupteba_YAF_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.YAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 05 03 44 24 24 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 c1 8d 0c 33 33 c1 2b f8 8b d7 c1 e2 04 81 3d } //1
		$a_03_1 = {8b 54 24 14 8b 44 24 10 33 d5 33 c2 2b f0 81 c3 ?? ?? ?? ?? ff 4c 24 18 89 44 24 10 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}