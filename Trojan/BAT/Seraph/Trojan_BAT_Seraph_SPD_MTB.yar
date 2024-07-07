
rule Trojan_BAT_Seraph_SPD_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 16 11 06 11 06 25 17 58 13 06 28 90 01 03 0a 11 06 06 1a 58 4a 31 e8 90 00 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}