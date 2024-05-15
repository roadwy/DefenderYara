
rule Trojan_BAT_NanoCoreRAT_G_MTB{
	meta:
		description = "Trojan:BAT/NanoCoreRAT.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {1b 11 09 11 07 11 0a 25 17 58 13 0a 91 08 61 d2 9c 1f 0c } //00 00 
	condition:
		any of ($a_*)
 
}