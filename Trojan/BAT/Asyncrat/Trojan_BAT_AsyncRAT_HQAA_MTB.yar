
rule Trojan_BAT_AsyncRAT_HQAA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.HQAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {04 25 2d 17 26 7e 90 01 01 00 00 04 fe 90 01 02 00 00 06 73 90 01 01 00 00 0a 25 80 90 01 01 00 00 04 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 0a 00 28 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 0b 2b 00 07 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}