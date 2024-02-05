
rule Trojan_BAT_Prynt_DDVF_MTB{
	meta:
		description = "Trojan:BAT/Prynt.DDVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 08 9a 16 9a 72 90 01 03 70 28 90 01 03 0a 2d 11 06 08 9a 16 9a 28 90 01 03 06 28 90 01 03 0a 2b 05 28 90 01 03 0a 06 08 9a 17 9a 28 90 01 03 06 28 90 01 03 0a 0d 09 07 06 08 9a 18 9a 6f 1e 00 00 0a 74 02 00 00 1b 28 90 01 03 06 28 90 01 03 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}