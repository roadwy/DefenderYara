
rule Trojan_BAT_Lazy_PSLS_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {14 0a 38 17 00 00 00 00 72 01 00 00 70 28 08 00 00 06 0a dd 06 00 00 00 26 dd 00 00 00 00 06 2c e6 06 2a } //00 00 
	condition:
		any of ($a_*)
 
}