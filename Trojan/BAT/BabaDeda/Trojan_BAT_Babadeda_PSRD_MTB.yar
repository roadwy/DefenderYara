
rule Trojan_BAT_Babadeda_PSRD_MTB{
	meta:
		description = "Trojan:BAT/Babadeda.PSRD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 28 cc 00 00 0a 0d 28 06 00 00 06 6f 90 01 03 0a 28 90 01 03 0a 72 da 09 00 70 28 90 01 03 0a 6f 90 01 03 0a 13 21 11 21 2c 0d 02 6f 90 01 03 06 6f 90 01 03 0a 00 00 00 17 73 90 01 03 0a 28 90 01 03 0a 6f 90 01 03 0a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}