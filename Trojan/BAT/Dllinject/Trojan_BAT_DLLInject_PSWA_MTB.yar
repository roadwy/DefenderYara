
rule Trojan_BAT_DLLInject_PSWA_MTB{
	meta:
		description = "Trojan:BAT/DLLInject.PSWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {20 3a 04 00 00 16 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 06 72 b7 02 00 70 28 90 01 01 00 00 06 72 d1 02 00 70 28 90 01 01 00 00 06 0c 25 7e 27 00 00 0a 07 6f 90 01 01 00 00 0a 17 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}