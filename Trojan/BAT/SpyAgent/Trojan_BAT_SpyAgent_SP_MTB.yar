
rule Trojan_BAT_SpyAgent_SP_MTB{
	meta:
		description = "Trojan:BAT/SpyAgent.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 07 8e 69 5d 02 06 08 07 28 90 01 03 06 9c 06 15 58 0a 06 16 fe 04 16 fe 01 13 05 11 05 2d df 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}