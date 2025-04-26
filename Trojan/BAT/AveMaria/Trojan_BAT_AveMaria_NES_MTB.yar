
rule Trojan_BAT_AveMaria_NES_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 06 6f 21 00 00 0a 0d 07 09 6f 22 00 00 0a 07 18 6f 23 00 00 0a 02 13 04 07 6f 24 00 00 0a 11 04 16 11 04 8e 69 6f 25 00 00 0a 13 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}