
rule Trojan_BAT_Heracles_MA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {08 07 6f 1b 00 00 0a 07 6f 1c 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 0d de 1e 08 2c 06 08 6f 1f 00 00 0a dc } //02 00 
		$a_01_1 = {6c 00 6c 00 64 00 2e 00 62 00 73 00 69 00 73 00 6a 00 6e 00 65 00 6e 00 78 00 63 00 6e 00 6e 00 78 00 4a 00 } //00 00 
	condition:
		any of ($a_*)
 
}