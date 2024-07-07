
rule Trojan_Win32_Glupteba_RPX_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {21 ff be c6 ae cd 97 31 03 21 f6 43 39 cb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4a 01 f6 31 0f 47 39 df 75 ea c3 52 8b 34 24 83 c4 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 04 c7 04 24 90 01 04 5e e8 21 00 00 00 31 32 b9 90 01 04 81 c2 01 00 00 00 81 c1 90 01 04 83 ec 04 89 1c 24 59 39 fa 75 d2 89 c9 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}