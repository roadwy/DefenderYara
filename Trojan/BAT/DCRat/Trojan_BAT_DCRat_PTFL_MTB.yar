
rule Trojan_BAT_DCRat_PTFL_MTB{
	meta:
		description = "Trojan:BAT/DCRat.PTFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 23 00 00 0a 17 59 28 90 01 01 01 00 0a 16 7e a8 08 00 04 02 1a 28 90 01 01 01 00 0a 11 05 0d 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}