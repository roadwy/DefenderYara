
rule Trojan_BAT_Rozena_SPXD_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SPXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {07 11 06 07 11 06 91 1e 59 20 90 01 03 00 5f d2 9c 11 06 17 58 13 06 11 06 07 8e 69 32 e2 90 00 } //03 00 
		$a_01_1 = {31 39 32 2e 31 36 38 2e 34 35 2e 32 33 37 } //00 00  192.168.45.237
	condition:
		any of ($a_*)
 
}