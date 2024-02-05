
rule Trojan_Win32_AveMaria_NEDK_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.NEDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b c6 33 d2 f7 f7 8a 44 14 18 30 04 1e 46 81 fe 00 d0 07 00 7c c2 } //01 00 
		$a_01_1 = {74 6f 70 6b 65 6b } //00 00 
	condition:
		any of ($a_*)
 
}