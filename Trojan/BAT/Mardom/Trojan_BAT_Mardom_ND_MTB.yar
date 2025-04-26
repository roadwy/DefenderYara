
rule Trojan_BAT_Mardom_ND_MTB{
	meta:
		description = "Trojan:BAT/Mardom.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 27 11 20 61 11 1d 19 58 61 11 32 61 d2 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}