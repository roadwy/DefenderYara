
rule Trojan_BAT_Heracles_AE_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {91 0c 06 07 02 07 91 08 61 07 1f 28 28 24 00 00 06 5a 1f 2c 28 24 00 00 06 5f 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}