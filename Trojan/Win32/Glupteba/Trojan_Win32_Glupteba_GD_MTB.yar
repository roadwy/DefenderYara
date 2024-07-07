
rule Trojan_Win32_Glupteba_GD_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c6 d3 e0 8b ce c1 e9 90 01 01 03 8d 90 02 10 03 85 90 02 10 33 c1 8b 8d 90 02 10 03 ce 33 c1 90 00 } //1
		$a_02_1 = {8b 45 7c 89 38 90 02 10 89 70 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Glupteba_GD_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c1 2b f8 89 6c 24 90 01 01 81 f3 07 eb dd 13 81 6c 24 14 90 01 04 b8 90 01 04 81 6c 24 14 90 01 04 81 44 24 14 90 01 04 8b 4c 24 90 01 01 8b 54 24 90 01 01 8b c7 d3 e0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}