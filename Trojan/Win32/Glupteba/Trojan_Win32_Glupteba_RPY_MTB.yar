
rule Trojan_Win32_Glupteba_RPY_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 17 09 db 89 f3 47 4e 39 cf 75 e3 c3 81 eb 01 00 00 00 09 db 8d 14 02 8b 12 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 ff 75 d4 8b 45 fc ff 50 18 8b 55 fc 89 42 28 8d 45 d8 50 8b 45 fc ff 50 1c 8b 45 fc 8b 55 dc 89 50 38 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_RPY_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4f 57 8b 34 24 83 c4 04 31 0b 43 81 ee 90 01 04 01 f6 39 d3 75 df 56 5f 47 c3 8d 0c 01 81 c7 01 00 00 00 8b 09 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_RPY_MTB_4{
	meta:
		description = "Trojan:Win32/Glupteba.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c7 33 c1 2b f0 89 44 24 10 8b c6 c1 e0 04 } //1
		$a_01_1 = {89 44 24 10 8b 44 24 24 01 44 24 10 03 de 31 5c 24 0c 8b 44 24 10 31 44 24 0c 8b 44 24 0c 29 44 24 14 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}