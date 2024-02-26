
rule Trojan_BAT_NjRat_MBFQ_MTB{
	meta:
		description = "Trojan:BAT/NjRat.MBFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 41 00 51 00 71 00 56 00 54 00 00 19 5b 00 2b 00 5d 00 5b 00 2b 00 5d 00 5b 00 2b 00 5d 00 5b 00 2b 00 5d 00 00 09 4c 00 6f 00 61 00 64 00 00 19 5b 00 2d 00 5d 00 5b 00 2d 00 5d 00 5b 00 2d 00 5d 00 5b 00 2d 00 5d 00 01 15 45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 } //00 00 
	condition:
		any of ($a_*)
 
}