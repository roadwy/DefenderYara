
rule Trojan_BAT_Heracles_PTEB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PTEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {2b 0b 80 88 00 00 0a 7e 88 00 00 0a 2a 28 90 01 01 00 00 2b 2b ee 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}