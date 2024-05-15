
rule Trojan_BAT_AmsiBypass_NB_MTB{
	meta:
		description = "Trojan:BAT/AmsiBypass.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {08 8e 69 5d 91 61 d2 9c 11 0d 17 58 } //00 00 
	condition:
		any of ($a_*)
 
}