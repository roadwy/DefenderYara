
rule Trojan_BAT_NjRat_NEAL_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {38 00 00 00 00 7e 1e 00 00 04 17 9a 28 45 00 00 0a 7e 20 00 00 04 28 37 00 00 06 28 45 00 00 0a 28 35 00 00 0a 80 1f 00 00 04 38 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}