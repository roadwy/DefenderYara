
rule Trojan_BAT_Bladabindi_PSMS_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.PSMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {6f 43 00 00 0a 26 72 1f 00 00 70 28 90 01 03 0a 00 28 06 00 00 06 6f 90 01 03 0a 72 43 00 00 70 72 1f 00 00 70 6f 90 01 03 0a 00 73 90 01 03 0a 0c 08 6f 90 01 03 0a 72 1f 00 00 70 6f 90 01 03 0a 00 08 6f 90 01 03 0a 26 72 1f 00 00 70 28 44 00 00 0a 00 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}