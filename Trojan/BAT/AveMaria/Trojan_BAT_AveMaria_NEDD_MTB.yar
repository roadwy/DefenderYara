
rule Trojan_BAT_AveMaria_NEDD_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 6a 00 28 04 00 00 06 73 1a 00 00 0a 0b 73 15 00 00 0a 0c 07 16 73 1b 00 00 0a 73 1c 00 00 0a 0d 09 08 6f 17 00 00 0a de 0a 09 2c 06 09 6f 1d 00 00 0a dc 08 6f 18 00 00 0a 13 04 de 34 08 2c 06 08 } //10
		$a_01_1 = {43 6c 69 65 6e 74 20 53 65 73 73 69 6f 6e 20 41 67 65 6e 74 } //2 Client Session Agent
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2) >=12
 
}