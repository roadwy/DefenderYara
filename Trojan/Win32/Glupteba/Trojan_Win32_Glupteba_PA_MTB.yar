
rule Trojan_Win32_Glupteba_PA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 44 24 20 01 44 24 14 8b 44 24 14 33 c3 33 44 24 10 c7 05 90 01 08 2b f0 89 44 24 14 8b c6 c1 e0 04 89 44 24 10 8b 44 24 24 01 44 24 10 8b d6 c1 ea 05 03 54 24 28 8d 04 37 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_PA_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {75 31 33 c0 8d 90 02 03 51 8d 90 02 03 52 50 89 90 02 03 89 90 02 03 89 90 02 03 89 90 02 03 89 90 02 03 ff d3 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff d5 57 e8 90 02 04 81 3d 90 02 08 75 0e 6a 00 ff 15 90 02 04 ff 15 90 02 04 83 c7 08 83 ee 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_PA_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 db 8a 93 90 01 03 00 30 11 43 81 fb 10 00 00 00 75 02 33 db 41 3b 0d 2c 80 48 00 75 90 00 } //01 00 
		$a_02_1 = {33 db 3b 05 90 01 03 00 74 2a 3b 05 90 01 03 00 74 15 8a 93 90 01 03 00 30 10 43 81 fb 10 00 00 00 75 0e 33 db eb 0a 03 05 90 01 03 00 33 db eb 90 01 01 40 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}