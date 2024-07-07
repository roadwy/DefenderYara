
rule Trojan_BAT_Zusy_NF_MTB{
	meta:
		description = "Trojan:BAT/Zusy.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e 90 01 01 08 00 04 0e 06 17 59 95 58 0e 05 28 de 0d 00 06 58 54 2a 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}