
rule Trojan_BAT_QuasarRAT_V_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 0d 09 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 02 7b 90 01 01 00 00 04 6f 90 01 01 00 00 0a 13 04 73 90 01 01 00 00 0a 13 05 08 73 90 01 01 00 00 0a 13 06 11 06 11 04 16 73 90 01 01 00 00 0a 13 07 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}