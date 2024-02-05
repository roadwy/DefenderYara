
rule Trojan_BAT_Redline_PSRB_MTB{
	meta:
		description = "Trojan:BAT/Redline.PSRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {02 1f 30 28 05 00 00 2b 28 90 01 03 2b 0b 73 7f 00 00 0a 28 90 01 03 0a 03 28 90 01 03 06 28 90 01 03 06 0c 08 73 81 00 00 0a 07 06 28 90 01 03 2b 28 90 01 03 2b 28 90 01 03 06 28 09 00 00 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}