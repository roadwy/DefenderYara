
rule Trojan_BAT_Androm_AAD_MTB{
	meta:
		description = "Trojan:BAT/Androm.AAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 3d 06 07 9a 6f 30 00 00 0a 7e 0d 00 00 04 28 2d 00 00 06 2c 05 28 2e 00 00 06 06 07 9a 6f 31 00 00 0a 7e 0e 00 00 04 28 2d 00 00 06 2c 05 28 2e 00 00 06 1f 64 28 32 00 00 0a 07 17 58 0b 07 06 8e 69 17 59 32 bb } //00 00 
	condition:
		any of ($a_*)
 
}