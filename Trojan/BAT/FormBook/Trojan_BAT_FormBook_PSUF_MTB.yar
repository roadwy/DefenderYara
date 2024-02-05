
rule Trojan_BAT_FormBook_PSUF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.PSUF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 df 8e fb 0e 0b 07 20 e7 8e fb 0e fe 01 0c 08 2c 09 20 1f 8f fb 0e 0b 00 2b 28 07 20 f1 8e fb 0e fe 01 0d 09 2c 09 20 18 8f fb 0e 0b 00 2b 13 00 20 07 8f fb 0e 0b 17 13 04 02 28 90 01 03 06 0a 2b 00 06 2a 90 00 } //01 00 
		$a_01_1 = {42 00 75 00 6e 00 69 00 66 00 75 00 5f 00 54 00 65 00 78 00 74 00 42 00 6f 00 78 00 } //00 00 
	condition:
		any of ($a_*)
 
}