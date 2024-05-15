
rule Trojan_BAT_Stealer_MU_MTB{
	meta:
		description = "Trojan:BAT/Stealer.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 65 00 00 0a 7e ea 00 00 04 07 06 6f 66 00 00 0a 28 67 00 00 0a 13 06 28 65 00 00 0a 11 06 16 11 06 8e 69 6f 66 00 00 0a 28 68 00 00 0a 13 07 } //00 00 
	condition:
		any of ($a_*)
 
}