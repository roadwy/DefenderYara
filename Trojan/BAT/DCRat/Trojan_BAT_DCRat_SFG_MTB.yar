
rule Trojan_BAT_DCRat_SFG_MTB{
	meta:
		description = "Trojan:BAT/DCRat.SFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 1d 00 00 0a 7e 02 00 00 04 6f 1e 00 00 0a 0a 7e 03 00 00 04 06 28 11 29 00 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}