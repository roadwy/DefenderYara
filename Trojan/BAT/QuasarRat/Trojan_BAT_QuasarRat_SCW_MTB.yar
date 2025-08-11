
rule Trojan_BAT_QuasarRat_SCW_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.SCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 18 00 00 04 28 f5 04 00 06 80 18 00 00 04 7e 08 00 00 04 28 f5 04 00 06 80 08 00 00 04 7e 09 00 00 04 28 f5 04 00 06 80 09 00 00 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}