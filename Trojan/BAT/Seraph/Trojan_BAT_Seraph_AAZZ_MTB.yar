
rule Trojan_BAT_Seraph_AAZZ_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 50 11 04 02 50 11 00 11 04 59 17 59 91 9c } //2
		$a_01_1 = {02 50 11 00 11 04 59 17 59 11 03 9c } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}