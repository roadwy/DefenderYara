
rule Trojan_BAT_DCRat_RDE_MTB{
	meta:
		description = "Trojan:BAT/DCRat.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 02 00 fe 0c 01 00 6f 79 03 00 0a 20 01 00 00 00 73 7a 03 00 0a 25 fe 0c 00 00 20 00 00 00 00 fe 0c 00 00 8e 69 6f 1d 00 00 0a 25 6f 7b 03 00 0a fe 0c 02 00 6f c8 01 00 0a fe 0e 00 00 fe 0c 02 00 6f 1e 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}