
rule Trojan_Win32_Glupteba_DSO_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DSO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 4d ec 8b 55 f4 8b f3 c1 ee 05 03 75 e4 03 f9 03 d3 33 fa 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } //2
		$a_01_1 = {8b 45 08 8b 4d fc 8b 55 f8 89 08 89 50 04 75 } //1
		$a_03_2 = {8b f3 c1 ee 05 03 74 24 ?? 03 f9 8d 14 2b 33 fa 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } //2
		$a_01_3 = {8b 4c 24 10 89 48 04 89 18 5f 5e 5d 5b 81 c4 38 04 00 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1) >=3
 
}