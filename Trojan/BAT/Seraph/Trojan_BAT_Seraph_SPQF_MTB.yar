
rule Trojan_BAT_Seraph_SPQF_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPQF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 2d 00 00 01 25 16 1f 2c 9d 28 90 01 03 0a 0d 7e 90 01 03 0a 13 04 16 13 05 16 13 06 16 13 07 2b 1f 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}