
rule Trojan_BAT_Spynoon_MHAA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.MHAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 0a 91 11 0e 61 07 11 0f 91 59 13 10 11 10 20 00 01 00 00 58 13 11 07 11 0a 11 11 20 ff 00 00 00 5f d2 9c 00 11 0a 17 58 13 0a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}