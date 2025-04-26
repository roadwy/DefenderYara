
rule Trojan_BAT_Heracles_MBZC_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}