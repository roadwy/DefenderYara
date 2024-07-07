
rule Trojan_BAT_Stealer_AAZF_MTB{
	meta:
		description = "Trojan:BAT/Stealer.AAZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 09 06 07 09 59 17 59 91 9c 06 07 09 59 17 59 11 04 9c 09 17 58 0d 09 16 2d d2 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}