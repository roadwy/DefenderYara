
rule Trojan_BAT_LokiBot_RDF_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {2a 72 02 7b 90 01 04 04 02 7b 90 01 04 6f 17 01 00 0a 5d 6f 18 01 00 0a 03 61 d2 2a 90 00 } //01 00 
		$a_01_1 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //01 00  GetProcAddress
		$a_01_2 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //01 00  LoadLibrary
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}