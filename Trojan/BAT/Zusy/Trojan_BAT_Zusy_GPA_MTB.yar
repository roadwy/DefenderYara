
rule Trojan_BAT_Zusy_GPA_MTB{
	meta:
		description = "Trojan:BAT/Zusy.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 0a 05 58 0e 04 5d 13 04 08 02 09 6f 90 01 01 00 00 0a 11 90 01 01 61 d1 6f 90 01 01 00 00 0a 26 00 09 17 58 0d 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}