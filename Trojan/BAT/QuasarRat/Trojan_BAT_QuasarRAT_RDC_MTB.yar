
rule Trojan_BAT_QuasarRAT_RDC_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 06 6f 2c 00 00 0a 1f 20 06 6f 2c 00 00 0a 8e 69 1f 20 59 6f 03 01 00 0a 13 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}