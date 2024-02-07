
rule Trojan_BAT_Formbook_RDB_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 00 35 00 74 00 46 00 76 00 55 00 38 00 45 00 59 00 } //02 00  Y5tFvU8EY
		$a_01_1 = {00 16 13 04 2b 31 00 08 09 11 04 6f 95 01 00 0a 13 05 08 09 11 04 6f 95 01 00 0a 13 06 11 06 28 96 01 00 0a 13 07 07 06 11 07 28 97 01 00 0a 9c 00 11 04 17 58 13 04 11 04 08 6f 98 01 00 0a fe 04 13 08 11 08 2d bf 06 17 58 0a 00 09 17 58 0d 09 08 6f 99 01 00 0a fe 04 13 09 11 09 2d a1 } //00 00 
	condition:
		any of ($a_*)
 
}