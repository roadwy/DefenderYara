
rule Trojan_BAT_Remcos_MR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 13 05 16 13 06 11 05 12 06 28 90 01 03 0a 07 11 04 18 6f 90 01 03 0a 06 28 90 01 03 0a 13 07 08 11 04 11 07 6f 90 01 03 0a de 0c 11 06 2c 07 11 05 28 90 01 03 0a dc 11 04 18 58 13 04 11 04 07 6f 90 01 03 0a 32 b8 90 00 } //01 00 
		$a_01_1 = {57 95 02 28 09 0a 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 2b 00 00 00 06 00 00 00 04 00 00 00 0a 00 00 00 01 00 00 00 2c 00 00 00 0f 00 00 00 01 } //00 00 
	condition:
		any of ($a_*)
 
}