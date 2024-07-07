
rule Trojan_BAT_Heracles_PSPI_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PSPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 28 90 01 03 06 13 03 20 00 00 00 00 7e 73 00 00 04 7b 3a 00 00 04 3a 0f 00 00 00 26 20 00 00 00 00 38 04 00 00 00 fe 0c 02 00 45 01 00 00 00 05 00 00 00 38 00 00 00 00 28 90 01 03 06 11 03 6f 90 01 03 0a 28 90 01 03 0a 28 0d 00 00 06 13 01 38 00 00 00 00 dd 9d ff ff ff 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}