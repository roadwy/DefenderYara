
rule Trojan_BAT_Redcap_ACP_MTB{
	meta:
		description = "Trojan:BAT/Redcap.ACP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 8b 00 00 70 28 90 01 03 06 17 2d 1c 26 28 90 01 03 0a 06 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 06 1a 2d 06 26 de 09 0a 2b e2 0b 2b f8 26 de cd 90 00 } //01 00 
		$a_01_1 = {0b 2b f8 02 06 91 1e 2d 15 26 02 06 02 07 91 9c 02 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e9 06 07 32 de } //00 00 
	condition:
		any of ($a_*)
 
}