
rule Trojan_BAT_Seraph_SPQ_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f 90 01 03 0a 11 04 17 58 13 04 11 04 07 8e 69 32 df 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}