
rule Trojan_BAT_SorvePotel_GDQ_MTB{
	meta:
		description = "Trojan:BAT/SorvePotel.GDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 06 11 04 11 06 91 08 11 06 08 8e 69 5d 91 61 d2 9c 11 06 17 58 13 06 11 06 09 32 e1 11 05 2a } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}