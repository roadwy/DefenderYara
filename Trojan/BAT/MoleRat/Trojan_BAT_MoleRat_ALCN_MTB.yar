
rule Trojan_BAT_MoleRat_ALCN_MTB{
	meta:
		description = "Trojan:BAT/MoleRat.ALCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 8e 69 1a 5d 0a 03 8e 69 1a 5b 0b 03 8e 69 8d 29 02 00 01 0c 02 7b fb 73 00 04 8e 69 1a 5b 0d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}