
rule Trojan_BAT_Heracles_SPBP_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SPBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 08 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}