
rule Trojan_Win32_Glupteba_MZ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {8d 3c 28 c1 e8 05 89 44 24 14 c7 05 [0-08] 8b 44 24 38 01 44 24 14 81 3d } //1
		$a_00_1 = {33 f7 31 74 24 14 8b 44 24 14 29 44 24 18 81 3d } //1
		$a_02_2 = {8b f0 8d 14 28 d3 e0 c1 ee 05 03 [0-06] 03 [0-06] 89 [0-06] 8b c8 e8 [0-04] 33 c6 89 [0-06] c7 05 [0-08] 8b [0-06] 29 [0-06] 81 3d } //2
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*2) >=2
 
}