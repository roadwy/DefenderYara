
rule Trojan_BAT_AveMaria_RFAK_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.RFAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 73 49 00 00 0a 0d 00 09 02 16 02 8e 69 6f 4a 00 00 0a 00 09 6f 4b 00 00 0a 00 08 6f 4c 00 00 0a 13 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}