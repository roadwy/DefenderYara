
rule Trojan_Win32_Glupteba_NG_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 0f 81 ea ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 89 d6 89 da 39 c7 75 e5 c3 09 d6 ?? ?? 81 c2 ?? ?? ?? ?? 21 d2 c3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Glupteba_NG_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 24 e0 bf eb 0b 26 3e 75 1e 35 ?? ?? ?? ?? d8 cc f3 63 } //3
		$a_03_1 = {71 1e d1 4c 72 ?? 4d 73 5b e0 5a bb ?? ?? ?? ?? 72 3a 4d d7 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}
rule Trojan_Win32_Glupteba_NG_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {33 d1 31 55 ?? 8b 4d ?? 8d 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 3d [0-04] 26 04 00 00 75 } //2
		$a_02_1 = {33 d1 31 55 ?? 8b 4d ?? 8d 85 ?? ?? ?? ?? 90 18 29 08 c3 } //1
		$a_02_2 = {8b c6 d3 e0 8b 8d ?? ?? ?? ?? 89 45 ?? 8d 45 ?? e8 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}