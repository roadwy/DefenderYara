
rule Trojan_BAT_zgRAT_AA_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 02 11 03 11 01 11 03 91 72 90 01 01 00 00 70 28 90 01 01 00 00 06 59 d2 9c 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}