
rule Trojan_Win32_Glupteba_NG_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {31 0f 81 ea 90 01 04 81 c7 90 01 04 89 d6 89 da 39 c7 75 e5 c3 09 d6 90 01 02 81 c2 90 01 04 21 d2 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_NG_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {33 d1 31 55 90 01 01 8b 4d 90 01 01 8d 85 90 01 04 e8 90 01 04 81 3d 90 02 04 26 04 00 00 75 90 00 } //01 00 
		$a_02_1 = {33 d1 31 55 90 01 01 8b 4d 90 01 01 8d 85 90 01 04 90 18 29 08 c3 90 00 } //01 00 
		$a_02_2 = {8b c6 d3 e0 8b 8d 90 01 04 89 45 90 01 01 8d 45 90 01 01 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}