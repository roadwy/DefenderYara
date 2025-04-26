
rule Trojan_BAT_NjRat_NEAF_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 02 8e 69 5d 02 06 02 8e 69 5d 91 03 06 03 8e 69 5d 91 61 28 ?? 00 00 0a 02 06 17 58 02 8e 69 5d 91 28 ?? 00 00 0a 59 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}