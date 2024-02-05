
rule Trojan_BAT_LokiBot_CXE_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CXE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 5a 03 00 70 6f 90 01 04 74 90 01 04 72 90 01 04 72 90 01 04 6f 90 01 04 17 8d 90 01 04 25 16 1f 2d 9d 6f 90 01 04 13 01 90 00 } //05 00 
		$a_03_1 = {11 02 11 05 11 01 11 05 9a 1f 10 28 90 01 04 d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}