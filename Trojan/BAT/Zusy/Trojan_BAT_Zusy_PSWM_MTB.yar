
rule Trojan_BAT_Zusy_PSWM_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PSWM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {12 00 28 1a 00 00 0a 7d 20 00 00 04 12 00 15 7d 1f 00 00 04 12 00 7c 20 00 00 04 12 00 28 03 00 00 2b 2a } //00 00 
	condition:
		any of ($a_*)
 
}