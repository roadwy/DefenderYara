
rule Trojan_BAT_RedLine_GPA_MTB{
	meta:
		description = "Trojan:BAT/RedLine.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 12 11 15 75 02 00 00 1b 11 16 11 08 58 11 19 59 93 61 07 75 02 00 00 1b 11 19 11 16 58 1f 11 58 11 10 5d 93 61 d1 7e 11 02 00 04 11 0a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}