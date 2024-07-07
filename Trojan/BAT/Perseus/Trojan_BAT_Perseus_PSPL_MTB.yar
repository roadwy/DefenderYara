
rule Trojan_BAT_Perseus_PSPL_MTB{
	meta:
		description = "Trojan:BAT/Perseus.PSPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 02 0a 28 26 90 01 03 28 90 01 03 06 28 90 01 03 0a 6f 90 01 03 0a 0b 28 90 01 03 0a 0c 08 28 90 01 03 0a 07 6f 90 01 03 0a 6f 90 01 03 0a 0d 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 06 28 90 01 03 0a 6f 90 01 03 0a 6f 90 01 03 0a 13 04 06 09 11 04 28 90 01 03 06 13 05 11 05 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}