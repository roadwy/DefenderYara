
rule Trojan_BAT_RevengeRat_AR_MTB{
	meta:
		description = "Trojan:BAT/RevengeRat.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 16 6a 2b 64 00 07 16 17 73 90 01 01 00 00 0a 0c 73 90 01 01 00 00 0a 0d 1f 40 8d 90 01 01 00 00 01 2b 3f 15 13 05 08 11 04 16 11 04 8e 69 6f 90 01 01 00 00 0a 13 05 2b 1c 09 11 04 16 11 05 6f 90 01 01 00 00 0a 00 08 11 04 16 11 04 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}