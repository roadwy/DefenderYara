
rule Trojan_Win32_Razy_CM_MTB{
	meta:
		description = "Trojan:Win32/Razy.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {01 f7 31 01 09 de 81 eb 90 01 04 81 c1 90 01 04 81 ef 90 01 04 29 db 39 d1 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Razy_CM_MTB_2{
	meta:
		description = "Trojan:Win32/Razy.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 bb 03 cf b1 8b 34 24 83 c4 04 31 0b 89 f6 43 39 c3 75 e0 } //02 00 
		$a_01_1 = {31 31 43 81 c3 5e be e3 40 81 c1 04 00 00 00 21 d3 81 c3 01 00 00 00 39 c1 75 e0 } //00 00 
	condition:
		any of ($a_*)
 
}