
rule Trojan_Win32_Glupteba_NV_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {33 d9 33 d8 89 90 02 03 89 90 02 05 8b 90 02 05 29 90 02 03 8b 90 02 05 29 90 02 03 4a 8b 90 02 03 0f 85 90 00 } //1
		$a_02_1 = {33 d1 33 d0 89 45 f8 89 90 02 05 8b 90 02 05 29 90 02 03 8b 90 02 05 29 90 02 08 8b 90 02 03 0f 85 90 00 } //1
		$a_02_2 = {88 14 38 40 3b c1 90 18 8b 90 02 05 8a 90 02 06 8b 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}