
rule Trojan_Win32_Glupteba_RPM_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {31 3e 81 c6 04 00 00 00 39 de 75 ef 09 c9 c3 } //01 00 
		$a_01_1 = {31 3b 01 c9 81 c3 04 00 00 00 81 e9 01 00 00 00 39 d3 75 e7 c3 } //00 00 
	condition:
		any of ($a_*)
 
}