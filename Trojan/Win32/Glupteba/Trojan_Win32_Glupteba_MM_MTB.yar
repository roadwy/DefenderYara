
rule Trojan_Win32_Glupteba_MM_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 ff d3 56 e8 90 01 04 83 c6 08 83 ef 01 75 90 0a 0c 00 75 90 00 } //01 00 
		$a_00_1 = {8b 44 24 10 33 c6 89 44 24 10 2b f8 } //00 00 
	condition:
		any of ($a_*)
 
}