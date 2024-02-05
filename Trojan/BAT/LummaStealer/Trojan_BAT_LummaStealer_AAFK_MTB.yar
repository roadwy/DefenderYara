
rule Trojan_BAT_LummaStealer_AAFK_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.AAFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {0a 25 08 28 90 01 01 00 00 06 25 17 28 90 01 01 00 00 06 25 18 28 90 01 01 00 00 06 25 06 28 90 01 01 00 00 06 28 90 01 01 00 00 06 07 16 07 8e 69 28 90 01 01 00 00 06 0d 20 90 01 01 00 00 00 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}