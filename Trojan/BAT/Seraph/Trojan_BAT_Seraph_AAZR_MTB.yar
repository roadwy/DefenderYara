
rule Trojan_BAT_Seraph_AAZR_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 00 11 07 11 00 11 01 11 07 59 17 59 91 9c } //2
		$a_01_1 = {11 00 11 01 11 07 59 17 59 11 08 9c } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}