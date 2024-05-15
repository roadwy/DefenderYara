
rule Trojan_BAT_LummaStealer_AMMB_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {05 11 0b 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 08 11 90 01 01 91 61 d2 81 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}