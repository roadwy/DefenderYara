
rule Trojan_Win32_GuLoader_RPF_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 34 39 dd 90 02 10 90 13 90 02 10 01 34 3a 90 02 10 90 13 90 02 10 81 34 3a 90 02 10 90 13 90 02 10 83 ef 90 02 10 90 13 90 02 10 83 c7 90 02 10 90 13 90 02 10 0f 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_GuLoader_RPF_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 34 24 02 5c 4a ba 90 02 10 90 13 90 02 10 90 13 90 02 10 90 13 8f 04 30 90 02 10 90 13 90 02 10 90 13 90 02 10 90 13 90 02 10 90 13 83 de 28 90 02 10 90 13 90 02 10 90 13 83 d6 24 90 02 10 90 13 90 13 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}