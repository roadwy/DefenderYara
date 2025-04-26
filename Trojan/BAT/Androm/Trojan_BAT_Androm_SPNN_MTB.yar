
rule Trojan_BAT_Androm_SPNN_MTB{
	meta:
		description = "Trojan:BAT/Androm.SPNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 13 08 07 08 91 11 07 61 07 11 08 91 59 20 00 01 00 00 58 13 09 07 08 11 09 20 ff 00 00 00 5f d2 9c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}