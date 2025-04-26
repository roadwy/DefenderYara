
rule Trojan_BAT_Heracles_GZZ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a d2 61 d2 81 09 00 00 01 08 17 58 0c 08 07 17 59 33 d3 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}