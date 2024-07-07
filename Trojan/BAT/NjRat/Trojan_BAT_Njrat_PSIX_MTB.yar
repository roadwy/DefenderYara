
rule Trojan_BAT_Njrat_PSIX_MTB{
	meta:
		description = "Trojan:BAT/Njrat.PSIX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 09 6f 4f 00 00 0a 28 90 01 03 0a 9c 20 08 00 00 00 fe 0e 0c 00 38 32 ff ff ff 11 06 11 05 17 73 90 01 03 0a 13 07 20 0c 00 00 00 fe 0e 0c 00 38 18 ff ff ff 11 07 6f 90 01 03 0a 20 15 00 00 00 38 0b ff ff ff 11 04 07 08 6f 81 00 00 0a 13 05 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}