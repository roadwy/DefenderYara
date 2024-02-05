
rule Trojan_BAT_Redline_NED_MTB{
	meta:
		description = "Trojan:BAT/Redline.NED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {16 0c 07 6f 24 00 00 0a 0d 09 69 13 04 11 04 8d 11 00 00 01 0a 38 18 00 00 00 07 06 08 11 04 6f 42 00 00 0a 13 05 08 11 05 58 0c 11 04 11 05 59 13 04 11 04 16 } //00 00 
	condition:
		any of ($a_*)
 
}