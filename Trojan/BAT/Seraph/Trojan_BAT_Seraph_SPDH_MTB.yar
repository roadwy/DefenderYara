
rule Trojan_BAT_Seraph_SPDH_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 91 61 11 90 02 0a 91 59 20 00 01 00 00 58 d2 9c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}