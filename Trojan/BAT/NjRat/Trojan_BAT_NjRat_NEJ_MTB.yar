
rule Trojan_BAT_NjRat_NEJ_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0a 06 73 14 00 00 0a 72 19 00 00 70 28 15 00 00 0a 28 02 00 00 06 28 16 00 00 0a 6f 17 00 00 0a 28 18 00 00 0a 00 06 28 19 00 00 0a 26 2a } //00 00 
	condition:
		any of ($a_*)
 
}