
rule Trojan_BAT_Heracles_GPD_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 11 08 59 20 00 01 00 00 58 20 ff 00 00 00 5f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}