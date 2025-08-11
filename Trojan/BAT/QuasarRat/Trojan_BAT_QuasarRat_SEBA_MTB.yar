
rule Trojan_BAT_QuasarRat_SEBA_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.SEBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 0b 00 00 04 0c 08 0b 07 1f 29 2e 12 2b 00 07 1f 2a 2e 02 2b 12 1f 26 80 0b 00 00 04 2b 09 1f 25 80 0b 00 00 04 2b 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}