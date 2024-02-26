
rule Trojan_BAT_Nanocore_AAVF_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.AAVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 04 11 07 11 02 11 07 91 20 e7 ad e7 fa 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 59 d2 9c 20 0e 00 00 00 38 90 01 01 fe ff ff 11 07 17 58 13 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}