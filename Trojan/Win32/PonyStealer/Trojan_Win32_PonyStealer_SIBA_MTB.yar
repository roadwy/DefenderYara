
rule Trojan_Win32_PonyStealer_SIBA_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.SIBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 38 4d 5a 90 90 00 90 18 90 02 05 48 90 02 0a 81 38 4d 5a 90 90 00 75 90 00 } //01 00 
		$a_03_1 = {81 38 4d 5a 90 90 00 75 90 01 01 90 02 20 8b 00 90 02 05 6a 40 90 02 05 68 00 90 01 01 00 00 90 02 05 bf 00 c0 00 00 90 02 05 57 90 02 05 57 90 02 05 29 3c 24 90 02 05 ff d0 90 00 } //01 00 
		$a_03_2 = {89 0c 38 fc 90 02 05 81 34 38 90 01 04 90 02 05 83 ef 04 90 18 90 02 05 8b 0c 3a 90 02 05 89 0c 38 90 02 05 81 34 38 90 01 04 90 02 05 83 ef 04 7d 90 01 01 90 02 05 ff e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}