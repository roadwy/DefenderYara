
rule Trojan_BAT_Heracles_KAX_MTB{
	meta:
		description = "Trojan:BAT/Heracles.KAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0d 11 0e 11 0d 11 0e 91 18 59 20 ff 00 00 00 5f d2 9c 11 0e 17 58 13 0e } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}