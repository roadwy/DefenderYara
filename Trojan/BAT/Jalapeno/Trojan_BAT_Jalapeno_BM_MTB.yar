
rule Trojan_BAT_Jalapeno_BM_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 39 01 00 04 20 ed e1 77 9c 20 a3 d1 43 a7 61 20 02 00 00 00 63 20 7f 4e ff 1e 61 7d 43 01 00 04 20 00 00 00 00 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}