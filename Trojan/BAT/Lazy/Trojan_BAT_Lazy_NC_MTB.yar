
rule Trojan_BAT_Lazy_NC_MTB{
	meta:
		description = "Trojan:BAT/Lazy.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 17 11 0a 11 13 11 17 9d 11 13 17 d6 13 13 00 12 16 90 01 02 01 00 0a 13 18 11 18 2d dc 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}