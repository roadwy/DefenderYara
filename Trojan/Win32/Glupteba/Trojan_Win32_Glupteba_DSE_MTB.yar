
rule Trojan_Win32_Glupteba_DSE_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {bb 87 d5 7c 3a 81 45 ?? 8c eb 73 22 8b 45 ?? 8b 4d ?? 8b d0 d3 e2 8b c8 c1 e9 05 03 4d ?? 03 55 ?? 89 35 ?? ?? ?? ?? 33 d1 8b 4d ?? 03 c8 33 d1 } //1
		$a_02_1 = {bb 87 d5 7c 3a 81 44 24 ?? 8c eb 73 22 8b 4c 24 ?? 8b c5 d3 e0 8b cd c1 e9 05 03 4c 24 ?? 03 44 24 ?? 89 3d ?? ?? ?? ?? 33 c1 8b 4c 24 ?? 03 cd 33 c1 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}