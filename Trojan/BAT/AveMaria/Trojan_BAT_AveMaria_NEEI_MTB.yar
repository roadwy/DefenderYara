
rule Trojan_BAT_AveMaria_NEEI_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {13 09 07 28 04 00 00 0a 13 0a 11 0a 28 05 00 00 0a 7e 06 00 00 04 6f 06 00 00 0a 7e 07 00 00 04 } //05 00 
		$a_01_1 = {43 00 3a 00 5c 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 5c 00 76 00 34 00 2e 00 30 00 2e 00 33 00 30 00 33 00 31 00 39 00 } //00 00  C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319
	condition:
		any of ($a_*)
 
}