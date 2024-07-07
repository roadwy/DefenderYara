
rule Trojan_BAT_Mardom_CCFW_MTB{
	meta:
		description = "Trojan:BAT/Mardom.CCFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 07 02 8e b7 5d 02 07 02 8e b7 5d 91 08 07 08 8e b7 5d 91 61 02 07 17 58 02 8e b7 5d 91 59 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}