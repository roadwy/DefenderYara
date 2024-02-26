
rule Trojan_BAT_NjRat_AAWL_MTB{
	meta:
		description = "Trojan:BAT/NjRat.AAWL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 8e 69 13 04 11 04 09 8e 69 fe 02 13 05 2b 03 0d 2b ed 11 05 2c 02 2b 05 2b 0d 0c 2b df 09 8e 69 13 04 2b 03 0b 2b cc 07 09 11 04 28 90 01 01 00 00 0a 2b 07 6f 90 01 01 00 00 0a 2b ad 06 09 6f 90 01 01 00 00 0a 2b 07 6f 90 01 01 00 00 0a 2b 95 06 09 6f 90 01 01 00 00 0a 2b 0a 6f 90 01 01 00 00 0a 38 90 01 01 ff ff ff 06 6f 90 01 01 00 00 0a 13 06 2b 0a 6f 90 01 01 00 00 0a 38 90 01 01 ff ff ff 11 06 02 16 02 8e 69 6f 90 01 01 00 00 0a 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}