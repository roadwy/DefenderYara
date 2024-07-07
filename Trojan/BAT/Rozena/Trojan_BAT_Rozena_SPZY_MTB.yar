
rule Trojan_BAT_Rozena_SPZY_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SPZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 8e 69 13 04 7e 90 01 03 0a 20 90 01 03 00 20 90 01 03 00 1f 40 28 90 01 03 06 13 05 09 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}