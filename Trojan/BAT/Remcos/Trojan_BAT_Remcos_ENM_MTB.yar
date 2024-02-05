
rule Trojan_BAT_Remcos_ENM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ENM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 03 11 07 91 08 11 07 08 8e 69 5d 91 61 09 61 d2 6f 90 01 03 0a 00 00 11 07 17 58 13 07 11 07 03 8e 69 fe 04 13 08 11 08 2d d4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}