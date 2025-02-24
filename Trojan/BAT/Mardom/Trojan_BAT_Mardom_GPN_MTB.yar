
rule Trojan_BAT_Mardom_GPN_MTB{
	meta:
		description = "Trojan:BAT/Mardom.GPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 d2 9c 20 05 00 00 00 38 66 ff ff ff 38 96 00 00 00 20 05 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}