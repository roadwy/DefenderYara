
rule Trojan_BAT_NjRat_NEPB_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 06 16 11 05 6f 73 00 00 0a 00 08 06 16 06 8e b7 6f 7f 00 00 0a 13 05 00 11 05 16 fe 02 13 06 11 06 2d db } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}