
rule Trojan_BAT_FormBook_AHC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 0b 16 0c 2b 90 01 03 0d 2b 31 00 07 08 09 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 00 7e 90 01 03 04 06 28 90 01 03 06 d2 9c 00 09 17 58 90 00 } //01 00 
		$a_01_1 = {53 00 6b 00 69 00 } //00 00  Ski
	condition:
		any of ($a_*)
 
}