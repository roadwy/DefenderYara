
rule Trojan_BAT_LummaStealer_SPPS_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.SPPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {91 07 08 07 8e 69 5d 1f 90 01 01 58 1f 90 01 01 58 1f 90 01 01 59 91 61 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}