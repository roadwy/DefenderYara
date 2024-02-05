
rule Trojan_Win32_AveMaria_NEET_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.NEET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {f7 f9 8b 45 e8 0f b6 0c 10 8b 55 f4 03 55 fc 0f b6 02 33 c1 8b 4d f4 03 4d fc 88 01 8b 55 fc 83 c2 01 89 55 fc eb c8 } //00 00 
	condition:
		any of ($a_*)
 
}