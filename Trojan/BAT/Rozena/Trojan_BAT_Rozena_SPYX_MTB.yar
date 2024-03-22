
rule Trojan_BAT_Rozena_SPYX_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SPYX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {8e 69 0b 7e 90 01 03 0a 20 00 10 00 00 20 00 30 00 00 1f 40 28 90 01 03 06 0c 06 16 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}