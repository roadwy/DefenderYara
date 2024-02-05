
rule Trojan_BAT_Lazy_PSVU_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSVU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 06 00 28 90 01 01 00 00 0a 72 9d 00 00 70 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 73 90 01 01 00 00 0a 0b 07 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}