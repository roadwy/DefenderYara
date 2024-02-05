
rule Trojan_Win32_Glupteba_RT_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 38 81 c0 04 00 00 00 89 d9 43 39 d0 75 90 01 01 09 f1 09 de c3 83 ec 04 90 01 03 2d 8b f0 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 39 81 c6 bd fb 42 88 21 d8 81 c1 04 00 00 00 81 c6 01 00 00 00 39 d1 75 90 01 01 bb 24 d1 40 86 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_RT_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 ee 05 89 74 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 31 4c 24 90 01 01 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}