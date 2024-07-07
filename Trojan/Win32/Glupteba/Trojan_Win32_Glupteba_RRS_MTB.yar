
rule Trojan_Win32_Glupteba_RRS_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RRS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b cf c1 e9 05 03 4c 24 90 01 01 c7 05 90 01 08 89 54 24 90 01 01 89 35 90 01 04 89 35 90 01 04 8b 44 24 90 01 01 31 44 24 90 01 01 81 3d 90 01 04 72 07 00 00 90 00 } //1
		$a_02_1 = {8b cb c1 e1 04 03 8d 90 01 04 8b c3 c1 e8 05 03 85 90 01 04 03 d3 33 ca 81 3d 90 01 04 72 07 00 00 c7 05 90 01 04 b4 1a 3a df 90 00 } //1
		$a_02_2 = {8b cf c1 e1 04 03 8d 90 01 04 8b c7 c1 e8 05 03 85 90 01 04 03 d7 33 ca 81 3d 90 01 04 72 07 00 00 c7 05 90 01 04 b4 1a 3a df 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}