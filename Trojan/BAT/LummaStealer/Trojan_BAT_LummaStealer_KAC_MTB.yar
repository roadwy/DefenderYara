
rule Trojan_BAT_LummaStealer_KAC_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {05 11 0d 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 11 01 11 11 91 61 d2 90 00 } //01 00 
		$a_03_1 = {11 01 11 03 91 11 01 11 15 91 58 20 00 90 01 01 00 00 5d 13 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}