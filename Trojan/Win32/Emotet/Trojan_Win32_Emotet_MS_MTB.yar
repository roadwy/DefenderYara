
rule Trojan_Win32_Emotet_MS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 02 5f 5d c3 90 09 21 00 33 c1 90 01 02 c7 05 90 01 08 01 05 90 01 04 90 01 02 8b 15 90 01 04 a1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_MS_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 b8 1b cb 06 00 a1 90 01 04 33 c1 8b ff c7 05 90 01 04 00 00 00 00 01 05 90 01 04 8b ff 8b 15 90 01 04 a1 90 01 04 89 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}