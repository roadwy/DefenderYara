
rule Trojan_BAT_NJRat_RS_MTB{
	meta:
		description = "Trojan:BAT/NJRat.RS!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {7e 0a 00 00 04 07 09 16 6f 2c 00 00 0a 13 04 12 04 28 2d 00 00 0a 6f 2e 00 00 0a 00 09 17 d6 0d 09 08 31 dc } //05 00 
		$a_01_1 = {7e 0a 00 00 04 6f 2f 00 00 0a 28 14 00 00 06 26 de 10 } //00 00 
	condition:
		any of ($a_*)
 
}