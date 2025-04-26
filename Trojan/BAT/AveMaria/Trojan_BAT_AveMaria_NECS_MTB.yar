
rule Trojan_BAT_AveMaria_NECS_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NECS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {0c 06 08 06 6f 19 00 00 0a 1e 5b 6f 1a 00 00 0a 6f 1b 00 00 0a 06 08 06 6f 1c 00 00 0a 1e 5b 6f 1a 00 00 0a 6f 1d 00 00 0a 06 17 6f 1e 00 00 0a } //10
		$a_03_1 = {11 04 09 16 09 8e 69 6f ?? 00 00 0a de 08 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*5) >=15
 
}