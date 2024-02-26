
rule Trojan_BAT_Redline_GMY_MTB{
	meta:
		description = "Trojan:BAT/Redline.GMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 38 90 01 04 06 08 08 28 90 01 03 0a 9c 07 08 03 08 03 8e 69 5d 91 9c 08 17 58 0c 08 20 00 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}