
rule Trojan_BAT_NjRat_GPPE_MTB{
	meta:
		description = "Trojan:BAT/NjRat.GPPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 03 20 00 7e 00 00 5d 91 0a 06 7e 03 00 00 04 03 1f 16 5d 28 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}