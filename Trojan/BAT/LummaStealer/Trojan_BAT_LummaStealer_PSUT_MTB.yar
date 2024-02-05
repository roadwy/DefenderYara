
rule Trojan_BAT_LummaStealer_PSUT_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.PSUT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {14 68 67 14 16 9a 26 16 2d f9 28 90 01 01 00 00 06 7e 19 00 00 04 28 90 01 01 00 00 06 80 1b 00 00 04 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}