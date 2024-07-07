
rule Trojan_BAT_Bsymem_SPCS_MTB{
	meta:
		description = "Trojan:BAT/Bsymem.SPCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 08 07 6f 90 01 03 0a 07 6f 90 01 03 0a 28 90 01 03 2b 28 90 01 03 2b 28 90 01 03 0a 72 01 00 00 70 6f 90 01 03 0a 0d d0 22 00 00 01 28 90 01 03 0a 09 72 4d 00 00 70 28 90 01 03 0a 16 8d 10 00 00 01 6f 90 01 03 0a 26 de 1e 90 00 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}