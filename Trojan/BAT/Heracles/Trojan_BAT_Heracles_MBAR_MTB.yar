
rule Trojan_BAT_Heracles_MBAR_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 02 6f 90 01 01 00 00 0a 0c 08 07 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 0d 07 6f 90 01 01 00 00 0a 09 2a 90 00 } //01 00 
		$a_01_1 = {70 61 79 6c 6f 61 64 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}