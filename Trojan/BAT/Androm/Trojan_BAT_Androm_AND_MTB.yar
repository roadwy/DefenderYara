
rule Trojan_BAT_Androm_AND_MTB{
	meta:
		description = "Trojan:BAT/Androm.AND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {fe 01 16 fe 01 13 42 11 42 2d 1e 00 14 13 0b 14 13 0c 11 0b 11 0c 6f 90 01 03 0a 13 0d 14 13 0e 11 0e 6f 90 01 03 0a 26 00 02 11 09 91 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}