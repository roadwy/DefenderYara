
rule Trojan_Win32_Glupteba_QT_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.QT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {31 0f 21 d8 81 c7 90 01 04 81 c6 90 01 04 39 d7 75 e7 81 c6 90 01 04 c3 81 c1 90 01 04 39 c7 75 e3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_QT_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.QT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 90 02 02 8b 90 02 02 03 90 02 02 89 90 02 02 8b 90 02 02 33 90 02 02 89 90 02 02 8b 90 02 02 33 90 02 02 89 90 02 02 8b 90 02 02 29 90 02 02 c7 90 02 06 8b 90 02 02 01 90 02 02 8b 90 02 02 2b 90 02 02 89 90 02 02 e9 90 00 } //01 00 
		$a_02_1 = {c1 ea 05 89 90 02 02 8b 90 02 02 03 90 02 02 89 90 02 02 8b 90 02 02 33 90 02 02 89 90 02 02 8b 90 02 02 33 90 02 02 89 90 02 02 8b 90 02 02 29 90 02 02 8b 90 02 02 29 90 02 02 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}