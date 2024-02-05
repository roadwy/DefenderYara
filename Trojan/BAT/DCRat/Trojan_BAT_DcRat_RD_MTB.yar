
rule Trojan_BAT_DcRat_RD_MTB{
	meta:
		description = "Trojan:BAT/DcRat.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {a2 25 1a 72 37 03 00 70 a2 25 1b 7e c2 00 00 04 28 dc 00 00 0a 28 07 02 00 06 a2 25 1c 72 9e 09 00 70 a2 25 1d 06 a2 25 1e 72 71 00 00 70 a2 28 f8 00 00 0a 0b 06 } //00 00 
	condition:
		any of ($a_*)
 
}