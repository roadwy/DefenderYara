
rule Trojan_BAT_Heracles_KAAB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.KAAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 18 11 09 11 27 11 22 61 19 11 1c 58 61 11 2a 61 d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}