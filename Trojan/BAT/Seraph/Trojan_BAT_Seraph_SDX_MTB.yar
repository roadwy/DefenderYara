
rule Trojan_BAT_Seraph_SDX_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 20 00 01 00 00 6f 90 01 03 0a 06 72 01 00 00 70 28 90 01 03 0a 6f 90 01 03 0a 06 72 5b 00 00 70 28 90 01 03 0a 6f 90 01 03 0a 06 06 6f 90 01 03 0a 06 6f 90 01 03 0a 6f 90 01 03 0a 0b 73 0a 00 00 0a 0c 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}