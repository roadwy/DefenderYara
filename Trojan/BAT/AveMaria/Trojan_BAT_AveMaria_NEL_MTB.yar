
rule Trojan_BAT_AveMaria_NEL_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0d 09 20 00 01 00 00 6f 4c 00 00 0a 00 09 08 6f 4d 00 00 0a 00 09 18 6f 4e 00 00 0a 00 09 6f 4f 00 00 0a 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}