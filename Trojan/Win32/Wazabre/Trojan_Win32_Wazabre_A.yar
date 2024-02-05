
rule Trojan_Win32_Wazabre_A{
	meta:
		description = "Trojan:Win32/Wazabre.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 1e 8b 7d f4 8b 75 fc 81 7c 37 fc fe fe fe fe 75 0e ff 75 1c ff 75 e4 e8 } //01 00 
		$a_03_1 = {66 c7 05 02 70 40 00 06 00 66 c7 05 06 70 40 00 11 00 66 c7 05 08 70 40 00 12 00 66 c7 05 0a 70 40 00 25 00 68 90 01 02 40 00 68 90 01 02 40 00 e8 90 01 02 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}