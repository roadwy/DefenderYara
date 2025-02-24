
rule Trojan_BAT_Heracles_SCXF_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SCXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {91 07 11 06 07 8e 69 5d 91 61 07 11 06 07 8e 69 5d 91 61 07 11 06 07 8e 69 5d 91 61 d2 9c 11 06 17 58 13 06 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}