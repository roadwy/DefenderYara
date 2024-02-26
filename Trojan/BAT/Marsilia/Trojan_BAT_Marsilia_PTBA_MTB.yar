
rule Trojan_BAT_Marsilia_PTBA_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.PTBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {6f 13 00 00 0a 14 28 90 01 01 00 00 0a 2d 03 14 2b 0b 07 6f 13 00 00 0a 28 90 01 01 00 00 0a 0c 07 08 14 6f 16 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}