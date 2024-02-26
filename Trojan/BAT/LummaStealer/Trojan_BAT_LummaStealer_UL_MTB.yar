
rule Trojan_BAT_LummaStealer_UL_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.UL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 02 4b 04 03 05 66 60 61 58 0e 07 0e 04 e0 95 58 7e 08 0a 00 04 0e 06 17 59 e0 95 58 0e 05 28 b4 2f 00 06 58 54 } //00 00 
	condition:
		any of ($a_*)
 
}