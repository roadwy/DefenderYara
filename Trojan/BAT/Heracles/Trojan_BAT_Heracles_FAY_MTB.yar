
rule Trojan_BAT_Heracles_FAY_MTB{
	meta:
		description = "Trojan:BAT/Heracles.FAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 09 07 09 91 06 09 06 8e 69 5d 91 61 d2 9c 20 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}