
rule Trojan_BAT_LummaStealer_CCCW_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.CCCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 07 06 07 93 1f 3c 28 90 01 04 61 02 61 d1 9d 38 90 01 04 1e 28 90 01 04 0c 2b b6 06 8e 69 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}