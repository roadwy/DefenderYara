
rule Trojan_BAT_Lazy_PSVR_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {28 37 00 00 0a 28 90 01 01 00 00 06 28 90 01 01 00 00 06 72 d6 01 00 70 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0c 08 2c 5f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}