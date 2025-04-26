
rule Trojan_BAT_NjRat_NEPA_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 07 02 07 91 1f 09 61 d2 9c 07 1f 09 58 0b 07 08 31 ed } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}