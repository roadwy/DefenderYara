
rule Trojan_BAT_Rhadamanthys_RS_MTB{
	meta:
		description = "Trojan:BAT/Rhadamanthys.RS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 28 12 00 00 06 0a 28 03 00 00 0a 06 6f 04 00 00 0a 28 05 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 0b de 03 } //00 00 
	condition:
		any of ($a_*)
 
}