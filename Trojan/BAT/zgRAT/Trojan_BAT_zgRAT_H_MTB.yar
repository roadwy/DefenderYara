
rule Trojan_BAT_zgRAT_H_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 0a 13 07 73 90 01 02 00 0a 13 05 11 06 73 90 01 02 00 0a 0c 08 11 07 16 73 90 01 02 00 0a 0d 09 11 05 6f 90 01 02 00 0a 11 05 6f 90 01 02 00 0a 13 08 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}