
rule Trojan_BAT_Exnet_MKC_MTB{
	meta:
		description = "Trojan:BAT/Exnet.MKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_01_0 = {62 11 05 11 0c 17 58 91 1f 10 62 60 11 05 11 0c 18 58 91 1e 62 60 11 05 11 0c 19 58 91 60 13 0d 11 0c 1a 58 13 0e 11 0e 11 0d 58 11 05 8e } //35
	condition:
		((#a_01_0  & 1)*35) >=35
 
}