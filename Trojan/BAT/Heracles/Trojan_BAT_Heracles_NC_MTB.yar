
rule Trojan_BAT_Heracles_NC_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 47 11 0c 11 10 11 0c 8e 69 5d 91 61 d2 52 00 11 10 17 58 13 10 11 10 11 0b 8e 69 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}