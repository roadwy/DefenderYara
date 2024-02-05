
rule Trojan_Win32_AveMaria_NEAQ_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.NEAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 00 ff d6 8b c7 6a 64 99 59 f7 f9 8a 84 15 30 ff ff ff 30 04 1f 47 81 ff 00 d0 07 00 7c cb } //01 00 
		$a_01_1 = {74 6f 70 6b 65 6b } //01 00 
		$a_01_2 = {52 61 74 6c 74 68 75 6e 6b 2e 64 6c 6c } //01 00 
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}