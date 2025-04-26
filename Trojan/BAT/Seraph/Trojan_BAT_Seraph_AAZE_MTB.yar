
rule Trojan_BAT_Seraph_AAZE_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 06 09 91 9c 08 17 25 2c f1 58 0c 09 17 25 2c ea 59 0d 09 16 2f e8 07 13 04 de 30 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}