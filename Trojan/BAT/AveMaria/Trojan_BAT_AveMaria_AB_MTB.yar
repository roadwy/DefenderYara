
rule Trojan_BAT_AveMaria_AB_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 16 5d 91 13 0d 07 11 0b 91 11 08 58 13 0e 11 0c 11 0d 61 13 0f 11 0f 11 0e 59 13 10 07 11 0a 11 10 11 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}