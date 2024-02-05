
rule Trojan_Win32_LokiBot_DB_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 03 c3 a3 90 01 04 a1 90 01 04 8a 80 90 01 04 34 b1 a2 90 01 04 a1 90 01 04 8a 15 90 01 04 88 10 83 05 e4 1b 47 00 02 90 90 43 81 fb 4d 5e 00 00 75 90 00 } //01 00 
		$a_03_1 = {bb ba 8a 02 00 6a 00 e8 90 01 04 90 90 4b 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}