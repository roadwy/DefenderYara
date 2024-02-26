
rule Trojan_BAT_Vidar_PTAX_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PTAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 22 00 00 0a 6f 23 00 00 0a 13 35 11 35 73 0b 00 00 06 80 03 00 00 04 7e 03 00 00 04 6f 0d 00 00 06 06 } //00 00 
	condition:
		any of ($a_*)
 
}