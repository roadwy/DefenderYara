
rule Trojan_BAT_Ratx_SM_MTB{
	meta:
		description = "Trojan:BAT/Ratx.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 11 04 11 07 09 11 07 91 08 11 07 08 8e 69 5d 91 61 d2 9c 00 11 07 17 58 13 07 11 07 09 8e 69 fe 04 13 08 11 08 2d d8 } //00 00 
	condition:
		any of ($a_*)
 
}