
rule Trojan_BAT_Zusy_PTHX_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PTHX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f fa 00 00 0a 13 04 02 0d 11 04 09 16 09 8e b7 6f f9 00 00 0a } //00 00 
	condition:
		any of ($a_*)
 
}