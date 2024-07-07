
rule Trojan_BAT_Rozena_SPAP_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SPAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 16 11 04 08 16 12 01 28 90 01 03 06 0a 06 15 28 90 01 03 06 26 2b 00 90 00 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}